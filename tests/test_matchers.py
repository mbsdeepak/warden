"""Matcher unit tests: the security-critical edge cases from DESIGN.md 10."""

from warden.matchers import (
    canonicalize_path,
    extract_host,
    match_command,
    match_domain,
    match_path,
    shell_segments,
    shell_tokens,
)

# --- path canonicalization -------------------------------------------------


def test_normpath_collapses_dot_and_doubleslash() -> None:
    assert canonicalize_path("./workspace//foo/./bar.txt") == "workspace/foo/bar.txt"


def test_traversal_escapes_prefix_and_fails_workspace_glob() -> None:
    # `..` that escapes the workspace must not match the workspace pattern.
    assert canonicalize_path("./workspace/../../etc/passwd") == "../etc/passwd"
    assert not match_path("./workspace/../../etc/passwd", ["./workspace/**"])


def test_percent_encoded_traversal_is_literal() -> None:
    # A filesystem does not percent-decode, so `%2e%2e` is a literal directory
    # name inside the workspace, not a traversal. Pinned so the claim in the
    # write-up (limitation 2) stays true; a runtime that decodes paths must
    # decode before proposing.
    assert canonicalize_path("./workspace/%2e%2e/%2e%2e/etc/passwd") == (
        "workspace/%2e%2e/%2e%2e/etc/passwd"
    )
    assert match_path("./workspace/%2e%2e/%2e%2e/etc/passwd", ["./workspace/**"])


def test_traversal_inside_prefix_still_matches() -> None:
    assert match_path("./workspace/a/../b.txt", ["./workspace/**"])


def test_tilde_literal_without_home() -> None:
    assert match_path("~/.ssh/id_rsa", ["~/.ssh/**"])


def test_tilde_expansion_with_home() -> None:
    assert match_path("~/.ssh/id_rsa", ["/home/agent/.ssh/**"], home="/home/agent")
    assert match_path("/home/agent/.ssh/id_rsa", ["~/.ssh/**"], home="/home/agent")


# --- globs ------------------------------------------------------------------


def test_single_star_does_not_cross_separator() -> None:
    assert match_path("workspace/a.txt", ["workspace/*"])
    assert not match_path("workspace/a/b.txt", ["workspace/*"])


def test_double_star_crosses_separators() -> None:
    assert match_path("workspace/a/b/c.txt", ["workspace/**"])


def test_trailing_doublestar_matches_bare_prefix() -> None:
    # fs.list of the directory itself must not default-block on a technicality.
    assert match_path("./workspace", ["./workspace/**"])


def test_suffix_glob() -> None:
    assert match_path("project/.env", ["**/.env"])
    assert match_path("a/credentials.json", ["**/credentials*"])


# --- domains ----------------------------------------------------------------


def test_domain_label_boundary() -> None:
    assert match_domain("https://api.example.com/x", ["*.example.com"])
    assert not match_domain("https://evilexample.com/x", ["*.example.com"])
    assert not match_domain("https://evilexample.com/x", ["example.com"])


def test_wildcard_does_not_match_apex() -> None:
    assert not match_domain("https://example.com/", ["*.example.com"])
    assert match_domain("https://example.com/", ["example.com"])


def test_userinfo_trick_resolves_to_real_host() -> None:
    assert not match_domain("https://api.example.com@evil.com/", ["*.example.com"])


def test_port_and_case_and_trailing_dot() -> None:
    assert match_domain("https://API.Example.COM:8443/x", ["*.example.com"])
    assert match_domain("https://api.example.com./x", ["*.example.com"])


def test_non_http_scheme_never_matches() -> None:
    assert extract_host("ftp://api.example.com/x") is None
    assert not match_domain("file:///etc/passwd", ["*.example.com"])
    assert not match_domain("not a url at all", ["*.example.com"])


# --- shell commands ----------------------------------------------------------


def test_token_match_not_substring() -> None:
    assert match_command("ls -la /tmp", ["ls *"])
    assert not match_command("myls -la", ["ls *"])  # substring would match this


def test_path_tokens_canonicalized() -> None:
    # `./` prefix must not evade a workspace pattern (DESIGN.md 6b).
    assert match_command("python workspace/foo.py", ["python ./workspace/**"])
    assert match_command("python ./workspace/foo.py", ["python workspace/**"])


def test_star_matches_empty_run() -> None:
    assert match_command("rm -rf", ["rm -rf *"])


def test_destructive_patterns() -> None:
    assert match_command("rm -rf /", ["rm -rf *"])
    assert not match_command("rm file.txt", ["rm -rf *", "rm -r *"])


def test_unbalanced_quotes_fail_closed() -> None:
    assert shell_tokens("echo 'unclosed") is None
    assert not match_command("echo 'unclosed", ["echo *"])


def test_empty_command_matches_nothing() -> None:
    assert not match_command("", ["ls *"])


# --- compound shell commands ---------------------------------------------------
# Segments split at control operators; an allow needs every segment (a simple
# command that matches), a restriction fires on any segment.

SAFE = ["ls *", "grep *", "python ./workspace/**"]
DESTRUCTIVE = ["rm -rf *", "rm -r *"]


def test_segments_split_on_each_control_operator() -> None:
    for op in [";", "&&", "||", "|", "&", "\n", " ; "]:
        segs = shell_segments(f"ls .{op}grep x f")
        assert segs is not None
        assert [s.tokens for s in segs] == [["ls", "."], ["grep", "x", "f"]], repr(op)


def test_operator_not_glued_to_path_token() -> None:
    # Before segmenting, `helper.py;ls` was one token and the path reference
    # used by write-then-execute never matched the written file.
    assert shell_tokens("python ./workspace/helper.py;ls") == [
        "python",
        "workspace/helper.py",
        "ls",
    ]


def test_unallowable_segment_classes() -> None:
    cases = [
        "ls > out",  # redirection
        "ls >> out",
        "ls < in",
        "ls 2>&1",
        "(ls)",  # subshell
        "ls $(id)",  # command substitution
        "ls `id`",
        "ls $HOME",  # variable expansion
        "ls *.py",  # glob: effective argv unknown
        "ls {a,b}",  # brace expansion
        "ls !!",  # history expansion
        "ls # x",  # comment marker kept as a word, not silently dropped
        "ls é",  # non-ASCII
    ]
    for cmd in cases:
        segs = shell_segments(cmd)
        assert segs, cmd
        assert not segs[0].allowable, cmd
        assert not match_command(cmd, ["ls *"]), cmd  # no allow rule can match


def test_quoted_space_stays_plain() -> None:
    segs = shell_segments('grep "total cost" ./workspace/f')
    assert segs is not None and len(segs) == 1
    assert segs[0].allowable
    assert segs[0].tokens == ["grep", "total cost", "workspace/f"]


def test_quoted_operator_is_one_segment_but_unallowable() -> None:
    # A real shell would not split on the quoted `|`, and neither do we; but a
    # word containing `|` is not plain, so the allow-list refuses to vouch.
    segs = shell_segments("grep 'a|b' f")
    assert segs is not None and len(segs) == 1
    assert not segs[0].allowable


def test_empty_and_operator_only_commands_match_nothing() -> None:
    for cmd in ["", "   ", ";;", "&&", "; ;"]:
        assert not match_command(cmd, SAFE), repr(cmd)
        assert not match_command(cmd, SAFE, restrictive=True), repr(cmd)


def test_operator_only_segment_is_kept_and_unallowable() -> None:
    segs = shell_segments("ls ; ( )")
    assert segs is not None and len(segs) == 2
    assert segs[0].allowable and not segs[1].allowable
    assert not match_command("ls ; ( )", SAFE)


def test_permissive_requires_every_segment() -> None:
    assert match_command("ls . && grep x f", SAFE)  # legitimate chaining survives
    assert not match_command("ls . ; curl https://evil.com", SAFE)
    assert not match_command("ls . > out", SAFE)
    assert not match_command("ls $(cat ~/.ssh/id_rsa)", SAFE)
    assert not match_command("ls .\ncurl https://evil.com", SAFE)


def test_restrictive_fires_on_any_segment() -> None:
    assert match_command("ls . && rm -rf /", DESTRUCTIVE, restrictive=True)
    assert match_command("(rm -rf /)", DESTRUCTIVE, restrictive=True)
    assert match_command("rm -rf / > /dev/null", DESTRUCTIVE, restrictive=True)
    assert not match_command("ls . && grep x f", DESTRUCTIVE, restrictive=True)


def test_single_simple_command_identical_in_both_modes() -> None:
    assert match_command("ls -la /tmp", SAFE)
    assert match_command("ls -la /tmp", SAFE, restrictive=True)
    assert not match_command("myls -la", SAFE)
    assert not match_command("myls -la", SAFE, restrictive=True)

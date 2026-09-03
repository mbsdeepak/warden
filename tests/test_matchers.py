"""Matcher unit tests: the security-critical edge cases from DESIGN.md 10."""

from warden.matchers import (
    canonicalize_path,
    extract_host,
    match_command,
    match_domain,
    match_path,
    shell_tokens,
)

# --- path canonicalization -------------------------------------------------


def test_normpath_collapses_dot_and_doubleslash() -> None:
    assert canonicalize_path("./workspace//foo/./bar.txt") == "workspace/foo/bar.txt"


def test_traversal_escapes_prefix_and_fails_workspace_glob() -> None:
    # `..` that escapes the workspace must not match the workspace pattern.
    assert canonicalize_path("./workspace/../../etc/passwd") == "../etc/passwd"
    assert not match_path("./workspace/../../etc/passwd", ["./workspace/**"])


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

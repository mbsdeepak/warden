"""Argument matchers: lexical path canonicalization, globs, domains, shell tokens.

All matching is lexical. warden judges *proposed* calls; the paths need not
exist on the judging machine, so nothing here touches the filesystem
(DESIGN.md section 5, limitation 5 for the symlink/TOCTOU consequences).
"""

from __future__ import annotations

import posixpath
import re
import shlex
from functools import lru_cache
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Paths


def canonicalize_path(raw: str, home: str | None = None) -> str:
    """Lexically canonicalize a path: `~` expansion (only when a home is
    configured in the policy), `.`/`..`/`//` resolution. `..` that escapes the
    prefix survives (normpath("workspace/../../etc") == "../etc"), which is
    exactly what keeps traversal from slipping past a workspace glob: the
    canonical form no longer matches the allow pattern and falls to the
    default action.
    """
    p = raw.strip()
    if home is not None:
        if p == "~":
            p = home
        elif p.startswith("~/"):
            p = home.rstrip("/") + p[1:]
    return posixpath.normpath(p)


@lru_cache(maxsize=4096)
def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path glob to a regex. `**` crosses `/`, `*` and `?` do not.
    A trailing `/**` also matches the bare prefix itself, so `workspace/**`
    matches `workspace` (an fs.list of the directory must not fall to the
    default action on a technicality).
    """
    out: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("/**", i):
            out.append("(?:/.*)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def match_path(path: str, patterns: list[str], home: str | None = None) -> bool:
    """True if the lexically canonicalized path matches any canonicalized glob."""
    canonical = canonicalize_path(path, home)
    return any(
        _glob_to_regex(canonicalize_path(pat, home)).match(canonical) for pat in patterns
    )


# ---------------------------------------------------------------------------
# Domains


def extract_host(url: str) -> str | None:
    """Hostname of an http(s) URL, lowercased, trailing dot stripped.
    None for anything unparseable or non-http(s): unknown schemes must fall
    through to no-match (and from there to the default action), never guess.
    Uses urlsplit's hostname so `https://api.example.com@evil.com/` resolves
    to evil.com (userinfo trick) and ports are stripped.
    """
    try:
        parts = urlsplit(url.strip())
        if parts.scheme not in ("http", "https"):
            return None
        host = parts.hostname
    except ValueError:
        return None
    if not host:
        return None
    return host.rstrip(".").lower()


def match_domain(url: str, patterns: list[str]) -> bool:
    """Label-boundary domain matching: `*.example.com` matches
    `api.example.com` but never `evilexample.com`, and not `example.com`
    itself (list both forms to cover both). Exact patterns match exactly.
    """
    host = extract_host(url)
    if host is None:
        return False
    for raw in patterns:
        pat = raw.strip().rstrip(".").lower()
        if pat.startswith("*."):
            if host.endswith(pat[1:]):  # pat[1:] keeps the leading dot: boundary
                return True
        elif host == pat:
            return True
    return False


# ---------------------------------------------------------------------------
# Shell commands


def shell_tokens(command: str, home: str | None = None) -> list[str] | None:
    """Tokenize a shell command; path-looking tokens are canonicalized with the
    same rules as the path matcher, so `python ./workspace/x.py` and
    `python workspace/x.py` are the same command to every consumer (matching
    here, and write-then-execute arming in the session layer).
    None on untokenizable input (unbalanced quotes): the caller treats that
    as no-match, which falls through to the policy's catch-all (fail closed).
    """
    try:
        raw = shlex.split(command, posix=True)
    except ValueError:
        return None
    return [
        canonicalize_path(t, home) if ("/" in t or t.startswith("~")) else t for t in raw
    ]


def _match_token_seq(pattern: list[str], tokens: list[str]) -> bool:
    """`*` as a whole pattern token matches any run of tokens (including
    empty); any other pattern token glob-matches exactly one command token.
    """
    if not pattern:
        return not tokens
    head, rest = pattern[0], pattern[1:]
    if head == "*":
        return any(_match_token_seq(rest, tokens[i:]) for i in range(len(tokens) + 1))
    if not tokens:
        return False
    if not _glob_to_regex(head).match(tokens[0]):
        return False
    return _match_token_seq(rest, tokens[1:])


def match_command(command: str, patterns: list[str], home: str | None = None) -> bool:
    """Token-aware command matching, never raw substring (DESIGN.md 6b)."""
    tokens = shell_tokens(command, home)
    if tokens is None:
        return False
    for pat in patterns:
        pat_tokens = shell_tokens(pat, home)
        if pat_tokens and _match_token_seq(pat_tokens, tokens):
            return True
    return False

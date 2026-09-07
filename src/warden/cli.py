"""CLI adapters: `check` (persistent store), `replay` (ephemeral store),
`validate` (policy lint).

Failure semantics (DESIGN.md section 8): a malformed line yields a block
decision and the stream continues; every failure path degrades to block,
never to allow. Exit codes: 0 all allowed, 1 at least one block,
2 flags but no blocks, 3 operational error (bad policy / unreadable input).
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from typing import TextIO

import typer

from warden.lint import lint_policy
from warden.overrides import Override, append_override, load_overrides
from warden.policy import Policy, PolicyError, load_policy
from warden.runner import StreamProcessor
from warden.schema import SEVERITY
from warden.session import release_quarantine
from warden.store import FlagRecord, MemoryStore, SqliteStore, StateStore

app = typer.Typer(add_completion=False, help="warden: an agentic tool-call firewall")
review_app = typer.Typer(add_completion=False, help="review and resolve flagged calls")
app.add_typer(review_app, name="review")

DEFAULT_STORE = Path(".warden/state.db")
DEFAULT_OVERRIDES = Path(".warden/overrides.yaml")

_EXIT_BY_SEVERITY = {0: 0, 1: 2, 2: 1}  # allow -> 0, flag -> 2, block -> 1


@app.callback()
def _root() -> None:
    """warden: an agentic tool-call firewall."""


def _load(policy_path: Path) -> Policy:
    """Load the policy or exit 3; print lint warnings to stderr either way."""
    try:
        policy = load_policy(policy_path)
    except PolicyError as exc:
        typer.echo(f"warden: {exc}", err=True)
        raise typer.Exit(3) from exc
    for warning in lint_policy(policy):
        typer.echo(f"warden: warning: {warning}", err=True)
    return policy


def _load_overrides_or_exit(path: Path | None) -> list[Override]:
    if path is None:
        return []
    try:
        return load_overrides(path)
    except PolicyError as exc:
        typer.echo(f"warden: {exc}", err=True)
        raise typer.Exit(3) from exc


def _run(
    policy: Policy,
    store: StateStore,
    input_file: str,
    audit: TextIO | None,
    max_sessions: int,
    overrides: list[Override],
) -> int:
    processor = StreamProcessor(
        policy, store, max_sessions=max_sessions, audit=audit, overrides=overrides
    )
    worst = 0

    def consume(stream: TextIO) -> None:
        nonlocal worst
        for line_no, line in enumerate(stream, start=1):
            decision = processor.process_line(line, line_no)
            if decision is None:
                continue
            sys.stdout.write(decision.to_json() + "\n")
            worst = max(worst, SEVERITY[decision.decision])

    try:
        if input_file == "-":
            # Python's default stdin decoder is strict, so raw non-UTF-8 bytes
            # on a pipe would raise before the line ever reached _parse. Decode
            # with replacement, as the file branch does, so garbage bytes become
            # a malformed-line block instead of a crash (fail closed, Section 8).
            buffer = getattr(sys.stdin, "buffer", None)
            stdin: TextIO = (
                io.TextIOWrapper(buffer, encoding="utf-8", errors="replace")
                if buffer is not None
                else sys.stdin
            )
            consume(stdin)
        else:
            with open(input_file, encoding="utf-8", errors="replace") as fh:
                consume(fh)
    except OSError as exc:
        typer.echo(f"warden: cannot read {input_file}: {exc}", err=True)
        raise typer.Exit(3) from exc
    finally:
        processor.finish()
    return _EXIT_BY_SEVERITY[worst]


def _open_audit(audit: Path | None) -> TextIO | None:
    if audit is None:
        return None
    audit.parent.mkdir(parents=True, exist_ok=True)
    return open(audit, "a", encoding="utf-8")


@app.command()
def check(
    input_file: str = typer.Argument("-", help="JSONL events file, or '-' for stdin"),
    policy: Path = typer.Option(..., "--policy", "-p", help="policy YAML file"),
    store: Path = typer.Option(
        DEFAULT_STORE, "--store", help="session state store (SQLite); persists across runs"
    ),
    audit: Path | None = typer.Option(None, "--audit", help="append decisions to this JSONL file"),
    overrides: Path = typer.Option(
        DEFAULT_OVERRIDES, "--overrides", help="minted exceptions file (review --remember)"
    ),
    max_sessions: int = typer.Option(1024, help="in-memory session working set bound (LRU)"),
) -> None:
    """Decide every tool call in a JSONL stream; emit one decision per line.

    Session state (taint, quarantine) persists in the store, so a later run
    honors what an earlier run learned (D8)."""
    pol = _load(policy)
    audit_fh = _open_audit(audit)
    try:
        code = _run(
            pol,
            SqliteStore(store),
            input_file,
            audit_fh,
            max_sessions,
            _load_overrides_or_exit(overrides),
        )
    finally:
        if audit_fh is not None:
            audit_fh.close()
    raise typer.Exit(code)


@app.command()
def replay(
    scenario: str = typer.Argument(..., help="scenario name (from ./scenarios) or JSONL path"),
    policy: Path = typer.Option(Path("policy.yaml"), "--policy", "-p", help="policy YAML file"),
    store: Path | None = typer.Option(
        None,
        "--store",
        help="opt into a persistent store; default is ephemeral so demos never"
        " pollute real state or leak quarantine between runs",
    ),
    audit: Path | None = typer.Option(None, "--audit", help="append decisions to this JSONL file"),
    overrides: Path | None = typer.Option(
        None,
        "--overrides",
        help="opt into a minted-exceptions file; default none so demos are self-contained",
    ),
) -> None:
    """Replay a bundled scenario (or any JSONL file) against the policy."""
    path = Path(scenario)
    if not path.exists() and "/" not in scenario:
        candidate = Path("scenarios") / f"{scenario}.jsonl"
        if candidate.exists():
            path = candidate
    pol = _load(policy)
    backing: StateStore = SqliteStore(store) if store is not None else MemoryStore()
    audit_fh = _open_audit(audit)
    try:
        code = _run(pol, backing, str(path), audit_fh, 1024, _load_overrides_or_exit(overrides))
    finally:
        if audit_fh is not None:
            audit_fh.close()
    raise typer.Exit(code)


# ---------------------------------------------------------------------------
# review: the flag -> human -> resolve loop (DESIGN.md section 7)

_STORE_OPT = typer.Option(DEFAULT_STORE, "--store", help="session state store (SQLite)")
_OVERRIDES_OPT = typer.Option(DEFAULT_OVERRIDES, "--overrides", help="minted exceptions file")


def _get_pending_flag(store: SqliteStore, flag_id: int) -> FlagRecord:
    flag = store.get_flag(flag_id)
    if flag is None:
        typer.echo(f"warden: no flag with id {flag_id}", err=True)
        raise typer.Exit(3)
    if flag.status != "pending":
        typer.echo(f"warden: flag {flag_id} already resolved ({flag.status})", err=True)
        raise typer.Exit(3)
    return flag


@review_app.command("list")
def review_list(store: Path = _STORE_OPT) -> None:
    """Pending flagged calls, one JSON record per line."""

    for flag in SqliteStore(store).pending_flags():
        typer.echo(
            json.dumps(
                {
                    "id": flag.id,
                    "call_id": flag.call_id,
                    "session_id": flag.session_id,
                    "tool": flag.event.tool,
                    "reason": flag.decision.reason,
                    "created_at": flag.created_at,
                }
            )
        )


@review_app.command("show")
def review_show(flag_id: int, store: Path = _STORE_OPT) -> None:
    """Full event, decision, and session context for one flag."""
    st = SqliteStore(store)
    flag = st.get_flag(flag_id)
    if flag is None:
        typer.echo(f"warden: no flag with id {flag_id}", err=True)
        raise typer.Exit(3)
    state = st.load(flag.session_id)
    context = {
        "flag": flag.model_dump(),
        "session": {
            "quarantined": state.quarantine.model_dump() if state and state.quarantine else None,
            "labels": {k: v.model_dump() for k, v in state.labels.items()} if state else {},
        },
    }

    typer.echo(json.dumps(context, indent=2))


@review_app.command("approve")
def review_approve(
    flag_id: int,
    remember: bool = typer.Option(
        False, "--remember", help="mint an exact-match exception so this call stops flagging"
    ),
    store: Path = _STORE_OPT,
    overrides: Path = _OVERRIDES_OPT,
) -> None:
    """Resolve a flag as allowed; --remember additionally mints an override."""
    st = SqliteStore(store)
    flag = _get_pending_flag(st, flag_id)
    if remember:
        state = st.load(flag.session_id)
        if state is not None and state.quarantine is not None:
            # D10: a minted static allow is outranked by the session layer
            # until release; minting a rule that silently does nothing is
            # worse than refusing.
            typer.echo(
                f"warden: refusing --remember: session {flag.session_id} is quarantined"
                f" (by seq.{state.quarantine.rule_id}), so a minted exception would have"
                f" no effect until `warden review release {flag.session_id}`."
                " Plain `approve` (without --remember) still works.",
                err=True,
            )
            raise typer.Exit(3)
        override = Override(
            id=f"ov-{flag.id}",
            tool=flag.event.tool,
            args=flag.event.args,
            reason=f"approved by review: {flag.decision.reason}",
            minted_from=str(flag.id),
            minted_at=flag.created_at or "unknown",
        )
        append_override(overrides, override)
        st.audit_event("override_minted", {"flag_id": flag.id, "override_id": override.id})
    st.resolve_flag(flag_id, "approved")
    st.audit_event("flag_approved", {"flag_id": flag_id, "remember": remember})
    typer.echo(f"flag {flag_id} approved" + (" (exception minted)" if remember else ""))


@review_app.command("deny")
def review_deny(flag_id: int, store: Path = _STORE_OPT) -> None:
    """Resolve a flag as denied."""
    st = SqliteStore(store)
    _get_pending_flag(st, flag_id)
    st.resolve_flag(flag_id, "denied")
    st.audit_event("flag_denied", {"flag_id": flag_id})
    typer.echo(f"flag {flag_id} denied")


@review_app.command("sessions")
def review_sessions(store: Path = _STORE_OPT) -> None:
    """Quarantined sessions, with the calls that tripped them."""

    for state in SqliteStore(store).quarantined_sessions():
        assert state.quarantine is not None
        typer.echo(json.dumps({"session_id": state.session_id, **state.quarantine.model_dump()}))


@review_app.command("release")
def review_release(session_id: str, store: Path = _STORE_OPT) -> None:
    """Release a quarantined session: only a human does this (D7)."""
    st = SqliteStore(store)
    state = st.load(session_id)
    if state is None:
        typer.echo(f"warden: unknown session {session_id}", err=True)
        raise typer.Exit(3)
    if state.quarantine is None:
        typer.echo(f"warden: session {session_id} is not quarantined", err=True)
        raise typer.Exit(3)
    detail: dict[str, object] = {
        "session_id": session_id,
        "was": state.quarantine.model_dump(),
    }
    release_quarantine(state)
    st.save(state)
    st.audit_event("session_released", detail)
    typer.echo(f"session {session_id} released")


@app.command()
def validate(
    policy: Path = typer.Option(..., "--policy", "-p", help="policy YAML file"),
) -> None:
    """Validate a policy file: strict schema check plus reachability lint."""
    pol = _load(policy)
    typer.echo(
        f"policy OK: {len(pol.rules)} static rules, {len(pol.taint.sources)} taint sources,"
        f" {len(pol.taint.sinks)} sinks, {len(pol.sequences)} sequence rules"
    )


if __name__ == "__main__":
    app()

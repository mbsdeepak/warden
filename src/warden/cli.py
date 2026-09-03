"""CLI adapters: `check` (persistent store), `replay` (ephemeral store),
`validate` (policy lint).

Failure semantics (DESIGN.md section 8): a malformed line yields a block
decision and the stream continues; every failure path degrades to block,
never to allow. Exit codes: 0 all allowed, 1 at least one block,
2 flags but no blocks, 3 operational error (bad policy / unreadable input).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO

import typer

from warden.lint import lint_policy
from warden.policy import Policy, PolicyError, load_policy
from warden.runner import StreamProcessor
from warden.schema import SEVERITY
from warden.store import MemoryStore, SqliteStore, StateStore

app = typer.Typer(add_completion=False, help="warden: an agentic tool-call firewall")

DEFAULT_STORE = Path(".warden/state.db")

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


def _run(
    policy: Policy,
    store: StateStore,
    input_file: str,
    audit: TextIO | None,
    max_sessions: int,
) -> int:
    processor = StreamProcessor(policy, store, max_sessions=max_sessions, audit=audit)
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
            consume(sys.stdin)
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
    max_sessions: int = typer.Option(1024, help="in-memory session working set bound (LRU)"),
) -> None:
    """Decide every tool call in a JSONL stream; emit one decision per line.

    Session state (taint, quarantine) persists in the store, so a later run
    honors what an earlier run learned (D8)."""
    pol = _load(policy)
    audit_fh = _open_audit(audit)
    try:
        code = _run(pol, SqliteStore(store), input_file, audit_fh, max_sessions)
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
        code = _run(pol, backing, str(path), audit_fh, max_sessions=1024)
    finally:
        if audit_fh is not None:
            audit_fh.close()
    raise typer.Exit(code)


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

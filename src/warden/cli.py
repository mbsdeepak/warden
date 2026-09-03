"""CLI adapter: `warden check` reads JSONL events, emits JSONL decisions.

Failure semantics (DESIGN.md section 8): a malformed line yields a block
decision and the stream continues; every failure path degrades to block,
never to allow. Exit codes: 0 all allowed, 1 at least one block,
2 flags but no blocks, 3 operational error (bad policy / unreadable input).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, TextIO

import typer
from pydantic import ValidationError

from warden.engine import Engine
from warden.policy import PolicyError, load_policy
from warden.schema import SEVERITY, Decision, ToolCallEvent

app = typer.Typer(add_completion=False, help="warden: an agentic tool-call firewall")


@app.callback()
def _root() -> None:
    """warden: an agentic tool-call firewall.

    Keeps typer in subcommand mode even while `check` is the only command
    (review/replay/serve are planned), so the CLI shape is stable.
    """

MAX_LINE_BYTES = 1_000_000

_EXIT_BY_SEVERITY = {0: 0, 1: 2, 2: 1}  # allow -> 0, flag -> 2, block -> 1


def _attributable(raw: Any, key: str) -> str | None:
    """Best-effort id/session_id extraction from a malformed event, so a
    schema-invalid event that still names its session counts toward that
    session (probing attribution, DESIGN.md 6b)."""
    if isinstance(raw, dict) and isinstance(raw.get(key), str) and raw[key]:
        return str(raw[key])
    return None


def _malformed(line_no: int, detail: str, raw: Any = None) -> Decision:
    return Decision(
        id=_attributable(raw, "id"),
        session_id=_attributable(raw, "session_id"),
        decision="block",
        rule="malformed",
        matched_rules=["malformed"],
        reason=f"line {line_no}: {detail}",
    )


def process_line(engine: Engine, line: str, line_no: int) -> Decision | None:
    """One JSONL line to one decision. None for blank lines (not events).
    Never raises: unparseable input becomes a block decision (fail closed).
    """
    if not line.strip():
        return None
    if len(line.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
        return _malformed(line_no, f"event exceeds {MAX_LINE_BYTES} bytes")
    try:
        raw = json.loads(line)
    except (ValueError, RecursionError) as exc:
        return _malformed(line_no, f"malformed JSON: {exc}")
    if not isinstance(raw, dict):
        return _malformed(line_no, "event must be a JSON object", raw)
    try:
        event = ToolCallEvent.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(part) for part in first["loc"]) or "event"
        return _malformed(line_no, f"invalid event: {loc}: {first['msg']}", raw)
    return engine.decide(event)


def _run_stream(engine: Engine, stream: TextIO, out: TextIO) -> int:
    worst = 0
    for line_no, line in enumerate(stream, start=1):
        decision = process_line(engine, line, line_no)
        if decision is None:
            continue
        out.write(decision.to_json() + "\n")
        worst = max(worst, SEVERITY[decision.decision])
    return _EXIT_BY_SEVERITY[worst]


@app.command()
def check(
    input_file: str = typer.Argument("-", help="JSONL events file, or '-' for stdin"),
    policy: Path = typer.Option(..., "--policy", "-p", help="policy YAML file"),
) -> None:
    """Decide every tool call in a JSONL stream; emit one decision per line."""
    try:
        engine = Engine(load_policy(policy))
    except PolicyError as exc:
        typer.echo(f"warden: {exc}", err=True)
        raise typer.Exit(3) from exc
    if input_file == "-":
        code = _run_stream(engine, sys.stdin, sys.stdout)
    else:
        try:
            with open(input_file, encoding="utf-8", errors="replace") as fh:
                code = _run_stream(engine, fh, sys.stdout)
        except OSError as exc:
            typer.echo(f"warden: cannot read {input_file}: {exc}", err=True)
            raise typer.Exit(3) from exc
    raise typer.Exit(code)


if __name__ == "__main__":
    app()

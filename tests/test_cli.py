"""CLI adapter: malformed input never crashes the stream; exit codes triage."""

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from warden.cli import app

runner = CliRunner()
POLICY = str(Path(__file__).parent.parent / "policy.yaml")


def _check(tmp_path: Path, lines: list[str]) -> tuple[int, list[dict[str, Any]]]:
    events = tmp_path / "events.jsonl"
    events.write_text("\n".join(lines) + "\n")
    # Always pass --store: without it, check writes to .warden/state.db in the
    # cwd, so a test run would leave flags in the operator's real review queue.
    result = runner.invoke(
        app, ["check", str(events), "--policy", POLICY, "--store", str(tmp_path / "s.db")]
    )
    decisions = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return result.exit_code, decisions


def _event(call_id: str, tool: str, **args: object) -> str:
    return json.dumps({"id": call_id, "session_id": "s-1", "tool": tool, "args": args})


def test_clean_stream_exits_zero(tmp_path: Path) -> None:
    code, decisions = _check(tmp_path, [_event("c-1", "fs.read", path="./workspace/a.txt")])
    assert code == 0
    assert decisions[0]["decision"] == "allow"


def test_any_block_exits_one(tmp_path: Path) -> None:
    code, decisions = _check(
        tmp_path,
        [
            _event("c-1", "fs.read", path="./workspace/a.txt"),
            _event("c-2", "fs.read", path="~/.ssh/id_rsa"),
        ],
    )
    assert code == 1
    assert [d["decision"] for d in decisions] == ["allow", "block"]


def test_flags_only_exit_two(tmp_path: Path) -> None:
    code, decisions = _check(tmp_path, [_event("c-1", "shell.exec", command="git push")])
    assert code == 2
    assert decisions[0]["decision"] == "flag"
    assert decisions[0]["flag_source"] == "rule"


def test_malformed_line_mid_stream_blocks_and_continues(tmp_path: Path) -> None:
    code, decisions = _check(
        tmp_path,
        [
            _event("c-1", "fs.read", path="./workspace/a.txt"),
            "{this is not json",
            _event("c-3", "fs.read", path="./workspace/b.txt"),
        ],
    )
    assert code == 1  # the malformed line is a block
    assert len(decisions) == 3
    assert decisions[1]["decision"] == "block"
    assert decisions[1]["rule"] == "malformed"
    assert "line 2" in decisions[1]["reason"]
    assert decisions[2]["decision"] == "allow"  # stream survived


def test_schema_invalid_event_is_attributable(tmp_path: Path) -> None:
    # session_id present but `tool` missing: blocked, and the session is named
    # (this is what lets probing count schema-invalid events, DESIGN.md 6b).
    code, decisions = _check(
        tmp_path, [json.dumps({"id": "c-1", "session_id": "s-9", "args": {}})]
    )
    assert code == 1
    assert decisions[0]["decision"] == "block"
    assert decisions[0]["session_id"] == "s-9"


def test_non_object_json_blocked(tmp_path: Path) -> None:
    code, decisions = _check(tmp_path, ['["not", "an", "object"]'])
    assert code == 1
    assert decisions[0]["rule"] == "malformed"


def test_oversized_line_blocked(tmp_path: Path) -> None:
    huge = json.dumps(
        {"id": "c-1", "session_id": "s-1", "tool": "fs.read", "args": {"path": "x" * 1_100_000}}
    )
    code, decisions = _check(tmp_path, [huge])
    assert code == 1
    assert "exceeds" in decisions[0]["reason"]


def test_blank_lines_skipped(tmp_path: Path) -> None:
    code, decisions = _check(
        tmp_path, ["", _event("c-1", "fs.read", path="./workspace/a.txt"), "   "]
    )
    assert code == 0
    assert len(decisions) == 1


def test_empty_file_is_clean(tmp_path: Path) -> None:
    code, decisions = _check(tmp_path, [])
    assert code == 0
    assert decisions == []


def test_non_utf8_bytes_on_stdin_block_without_crash(tmp_path: Path) -> None:
    # The file branch already decodes with errors="replace"; stdin must match.
    # Raw binary on a pipe used to raise UnicodeDecodeError before _parse ran.
    garbage = b"\xc8\xff\xfe not utf-8 \x00\x9f\n"
    valid = _event("c-2", "fs.read", path="./workspace/a.txt").encode() + b"\n"
    result = runner.invoke(
        app,
        ["check", "-", "--policy", POLICY, "--store", str(tmp_path / "s.db")],
        input=garbage + valid,
    )
    # CliRunner records a normal non-zero exit as SystemExit; anything else
    # (UnicodeDecodeError before the fix) is a crash. Exit code alone cannot
    # tell them apart, since the runner also reports 1 for an uncaught exception.
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    assert result.exit_code == 1  # the garbage line is a block
    decisions = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    assert len(decisions) == 2
    assert decisions[0]["rule"] == "malformed"
    assert "line 1" in decisions[0]["reason"]
    assert decisions[1]["decision"] == "allow"  # stream survived


def test_bad_policy_exits_three(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\ndefault_action: permit\n")
    store = ["--store", str(tmp_path / "s.db")]
    result = runner.invoke(app, ["check", "-", "--policy", str(bad), *store])
    assert result.exit_code == 3


def test_missing_input_file_exits_three(tmp_path: Path) -> None:
    # The store is constructed before the input file is opened, so even this
    # exit-3 path would create .warden/state.db in the cwd without --store.
    store = ["--store", str(tmp_path / "s.db")]
    result = runner.invoke(app, ["check", "/nonexistent/events.jsonl", "--policy", POLICY, *store])
    assert result.exit_code == 3

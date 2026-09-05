"""The bundled scenarios, asserted exactly: these double as the demo.

Each scenario exists to prove one design claim (DESIGN.md section 9); the
assertion names the claim. Run via the CLI to also cover exit-code triage.
"""

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from warden.cli import app

runner = CliRunner()
ROOT = Path(__file__).parent.parent
POLICY = str(ROOT / "policy.yaml")


def replay(name: str) -> tuple[int, list[dict[str, Any]]]:
    result = runner.invoke(
        app, ["replay", str(ROOT / "scenarios" / f"{name}.jsonl"), "--policy", POLICY]
    )
    decisions = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return result.exit_code, decisions


def test_clean_workflow_all_allowed() -> None:
    # The requirement is "without breaking legitimate agent workflows":
    # list, read, GET, write, grep-what-you-wrote all pass. Exit 0.
    code, decisions = replay("clean-workflow")
    assert code == 0
    assert [d["decision"] for d in decisions] == ["allow"] * 5


def test_pii_processing_flags_not_blocks() -> None:
    # D9: local processing after a PII read goes to a human, it is not killed.
    code, decisions = replay("pii-processing")
    assert code == 2  # flags pending, no blocks
    assert [d["decision"] for d in decisions] == ["allow", "flag"]
    assert decisions[1]["rule"] == "taint.exfil-shell"


def test_exfil_chain_blocked_by_taint_not_static() -> None:
    # The POST goes to an ALLOWED domain: static policy passes it, and only
    # the session layer catches the chain. That is the differentiator claim.
    code, decisions = replay("exfil-chain")
    assert code == 1
    assert [d["decision"] for d in decisions] == ["allow", "allow", "block"]
    final = decisions[2]
    assert final["rule"] == "taint.exfil-post"
    assert "static.http-known-apis" in final["matched_rules"]
    assert "x-1" in final["reason"]  # provenance: the tainting call


def test_write_then_execute_blocked() -> None:
    code, decisions = replay("write-then-execute")
    assert code == 1
    assert [d["decision"] for d in decisions] == ["allow", "allow", "block"]
    assert decisions[2]["rule"] == "seq.write-then-execute"


def test_probing_quarantines_session() -> None:
    code, decisions = replay("probing")
    assert code == 1
    assert [d["decision"] for d in decisions] == ["block", "block", "block", "flag", "flag"]
    assert decisions[3]["rule"] == "session.quarantine"
    assert decisions[3]["flag_source"] == "quarantine"


def test_malformed_garbage_never_crashes() -> None:
    # Two unparseable lines (unattributable), three attributable schema-invalid
    # events (which quarantine s-mal), then a valid call flagged by quarantine.
    code, decisions = replay("malformed-garbage")
    assert code == 1
    assert [d["decision"] for d in decisions] == ["block"] * 5 + ["flag"]
    assert decisions[5]["flag_source"] == "quarantine"


def test_replay_is_deterministic_and_isolated() -> None:
    # Same scenario twice: identical output, because each replay run gets an
    # ephemeral store (a leaked quarantine would break this).
    first = replay("probing")
    second = replay("probing")
    assert first == second


def test_shell_chaining_allow_is_conjunctive_restriction_disjunctive() -> None:
    # Legitimate chaining (ls && grep) stays allowed; an exfil chain riding an
    # `ls` allow falls to the catch-all; a destructive second half blocks; a
    # chained execute of a just-written file still trips write-then-execute.
    code, decisions = replay("shell-chaining")
    assert code == 1
    expected = ["allow", "allow", "allow", "flag", "block", "block"]
    assert [d["decision"] for d in decisions] == expected
    assert decisions[3]["rule"] == "static.shell-anything-else"
    assert decisions[4]["rule"] == "static.shell-destructive"
    assert decisions[5]["rule"] == "seq.write-then-execute"

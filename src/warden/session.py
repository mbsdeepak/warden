"""Session layer: taint tracking, sequence rules, quarantine.

Session state is a pure data object owned by the adapter (D8); this module
only computes verdicts from state (`evaluate`) and state transitions from
decisions (`update`). Execution semantics are D5/D11: an allowed call
executed, a flagged call is assumed executed (pessimistic), a blocked call
never executed, and that single rule governs both taint sources and
sequence-step arming.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from warden.engine import Verdict, _spec_matches
from warden.matchers import canonicalize_path, shell_tokens
from warden.policy import Policy, SequenceRule
from warden.schema import Action, Decision, ToolCallEvent

EXECUTED_ACTIONS: frozenset[str] = frozenset({"allow", "flag"})


class TaintProvenance(BaseModel):
    call_id: str
    source_id: str
    detail: str  # e.g. the canonicalized path that was read


class CaptureEntry(BaseModel):
    position: int  # session call counter when captured
    call_id: str
    path: str  # canonicalized


class QuarantineInfo(BaseModel):
    rule_id: str
    trigger_call_ids: list[str]
    at_position: int


class WindowEntry(BaseModel):
    call_id: str | None  # None for unparseable-but-attributable inputs
    action: Action


class SessionState(BaseModel):
    """Everything warden remembers about one session. Serializable, so the
    adapter can persist it (D8) and a later run can honor it."""

    session_id: str
    counter: int = 0
    window: list[WindowEntry] = Field(default_factory=list)
    labels: dict[str, TaintProvenance] = Field(default_factory=dict)
    captures: dict[str, list[CaptureEntry]] = Field(default_factory=dict)
    quarantine: QuarantineInfo | None = None


def release_quarantine(state: SessionState) -> None:
    """Human adjudication of a quarantined session. Clears the quarantine AND
    the recent-call window: the blocks that tripped it have been reviewed, and
    leaving them in the window would re-quarantine the session on its very
    next call, making release a one-call illusion. Taint labels survive:
    releasing a quarantine is not a declassification of what the session read.
    """
    state.quarantine = None
    state.window = []


def _max_window(policy: Policy) -> int:
    return max((seq.when.within_calls for seq in policy.sequences), default=0)


def _referenced_paths(event: ToolCallEvent, home: str | None) -> set[str]:
    """Canonicalized paths this event refers to: shell token paths for
    shell.exec, args.path otherwise."""
    if event.tool == "shell.exec":
        command = event.args.get("command")
        if not isinstance(command, str):
            return set()
        tokens = shell_tokens(command, home)
        return {t for t in tokens if "/" in t or t.startswith("~")} if tokens else set()
    path = event.args.get("path")
    return {canonicalize_path(path, home)} if isinstance(path, str) else set()


def evaluate(policy: Policy, state: SessionState, event: ToolCallEvent) -> list[Verdict]:
    """Session-layer verdicts for one event, given state from prior calls.
    Pure: no state mutation here; `update` runs after the decision."""
    verdicts: list[Verdict] = []

    for sink in policy.taint.sinks:
        if event.tool in sink.tools and sink.when_label in state.labels:
            prov = state.labels[sink.when_label]
            verdicts.append(
                Verdict(
                    action=sink.action,
                    rule=f"taint.{sink.id}",
                    reason=(
                        f"{sink.reason} (session tainted '{sink.when_label}' "
                        f"by call {prov.call_id} reading {prov.detail})"
                    ),
                    layer="session",
                    explicit=True,
                )
            )

    for seq in policy.sequences:
        if seq.when.pattern is None or seq.action is None:
            continue
        step2 = seq.when.pattern[1]
        if event.tool != step2.tool:
            continue
        # Sequence steps are restriction, never permission: any segment of a
        # compound shell command that matches is enough (`ls . ; python x.py`).
        if step2.match is not None and not _spec_matches(
            step2.match, event, policy.home, restrictive=True
        ):
            continue
        referenced = _referenced_paths(event, policy.home)
        horizon = state.counter - seq.when.within_calls + 1
        for cap in state.captures.get(seq.id, []):
            if cap.position >= horizon and cap.path in referenced:
                verdicts.append(
                    Verdict(
                        action=seq.action,
                        rule=f"seq.{seq.id}",
                        reason=(
                            f"{seq.reason} ({cap.path} written by call "
                            f"{cap.call_id}, {state.counter - cap.position} calls ago)"
                        ),
                        layer="session",
                        explicit=True,
                    )
                )
                break

    if state.quarantine is not None:
        q = state.quarantine
        verdicts.append(
            Verdict(
                action="flag",
                rule="session.quarantine",
                reason=(
                    f"session quarantined by seq.{q.rule_id} (triggered by calls "
                    f"{', '.join(q.trigger_call_ids)}); calls need review until released"
                ),
                layer="session",
                explicit=True,
                source="quarantine",
            )
        )

    return verdicts


def _arm_captures(
    policy: Policy, state: SessionState, event: ToolCallEvent, seq: SequenceRule
) -> None:
    assert seq.when.pattern is not None
    step1 = seq.when.pattern[0]
    if event.tool != step1.tool:
        return
    if step1.match is not None and not _spec_matches(
        step1.match, event, policy.home, restrictive=True
    ):
        return
    path = event.args.get("path")
    if not isinstance(path, str):
        return
    entries = state.captures.setdefault(seq.id, [])
    entries.append(
        CaptureEntry(
            position=state.counter,
            call_id=event.id,
            path=canonicalize_path(path, policy.home),
        )
    )
    horizon = state.counter - seq.when.within_calls + 1
    state.captures[seq.id] = [c for c in entries if c.position >= horizon]


def update(
    policy: Policy,
    state: SessionState,
    decision: Decision,
    event: ToolCallEvent | None,
) -> None:
    """Apply one decided call to session state. `event` is None for
    unparseable-but-attributable inputs: they still occupy a window slot and
    count toward min_blocked (a session emitting garbage is either broken or
    probing; fail closed does not distinguish), but they can never taint or
    arm a capture (nothing executed)."""
    state.counter += 1
    state.window.append(WindowEntry(call_id=decision.id, action=decision.decision))
    max_window = _max_window(policy)
    if len(state.window) > max_window:
        state.window = state.window[-max_window:] if max_window else []

    if event is not None and decision.decision in EXECUTED_ACTIONS:
        for source in policy.taint.sources:
            if (
                source.label not in state.labels
                and event.tool == source.tool
                and _spec_matches(source.match, event, policy.home, restrictive=True)
            ):
                path = event.args.get("path")
                detail = (
                    canonicalize_path(path, policy.home) if isinstance(path, str) else event.tool
                )
                state.labels[source.label] = TaintProvenance(
                    call_id=event.id, source_id=source.id, detail=detail
                )
        for seq in policy.sequences:
            if seq.when.pattern is not None:
                _arm_captures(policy, state, event, seq)

    if state.quarantine is None:
        for seq in policy.sequences:
            if seq.when.min_blocked is None or seq.escalate != "quarantine":
                continue
            recent = state.window[-seq.when.within_calls :]
            blocked = [e for e in recent if e.action == "block"]
            if len(blocked) >= seq.when.min_blocked:
                state.quarantine = QuarantineInfo(
                    rule_id=seq.id,
                    trigger_call_ids=[e.call_id or "<unparseable>" for e in blocked],
                    at_position=state.counter,
                )
                break

"""Stream processing: one JSONL line in, one decision out, session state
threaded through the store (D8). Shared by `check` and `replay`; the only
difference between them is which store the cache wraps.
"""

from __future__ import annotations

import json
from typing import Any, TextIO

from pydantic import ValidationError

from warden import session
from warden.engine import Engine
from warden.policy import Policy
from warden.schema import Decision, ToolCallEvent
from warden.store import SessionCache, StateStore

MAX_LINE_BYTES = 1_000_000


def _attributable(raw: Any, key: str) -> str | None:
    """Best-effort id/session_id from a malformed event, so a schema-invalid
    event that still names its session counts toward that session's window
    (probing attribution, DESIGN.md 6b)."""
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


def _parse(line: str, line_no: int) -> ToolCallEvent | Decision | None:
    """None for blank lines; a Decision for anything unparseable (fail
    closed); a ToolCallEvent otherwise. Never raises."""
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
        return ToolCallEvent.model_validate(raw)
    except ValidationError as exc:
        first = exc.errors()[0]
        loc = ".".join(str(part) for part in first["loc"]) or "event"
        return _malformed(line_no, f"invalid event: {loc}: {first['msg']}", raw)


class StreamProcessor:
    """Decides a stream of events against one policy + one state store."""

    def __init__(
        self,
        policy: Policy,
        store: StateStore,
        max_sessions: int = 1024,
        audit: TextIO | None = None,
    ) -> None:
        self._policy = policy
        self._engine = Engine(policy)
        self._cache = SessionCache(store, max_sessions)
        self._audit = audit

    def process_line(self, line: str, line_no: int) -> Decision | None:
        parsed = _parse(line, line_no)
        if parsed is None:
            return None
        if isinstance(parsed, Decision):
            # Unparseable input: blocked. If it named a session, it occupies a
            # window slot there (counts toward min_blocked) but can never
            # taint or arm anything (nothing executed).
            if parsed.session_id is not None:
                state = self._cache.get(parsed.session_id)
                session.update(self._policy, state, parsed, event=None)
            decision = parsed
        else:
            state = self._cache.get(parsed.session_id)
            verdicts = session.evaluate(self._policy, state, parsed)
            decision = self._engine.decide(parsed, verdicts)
            session.update(self._policy, state, decision, parsed)
        if self._audit is not None:
            self._audit.write(decision.to_json() + "\n")
        return decision

    def finish(self) -> None:
        """Flush the working set to the store. Call once per stream."""
        self._cache.flush()

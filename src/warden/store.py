"""State persistence (D8): session state, the pending-flag queue, audit events.

The engine never touches storage; adapters own it. SqliteStore is the real
store (one operator, one writer: limitation 7); MemoryStore backs `replay`
so demos can never pollute real state or leak quarantine between runs.
Only rule-source flags enter the queue (D10): quarantine-induced flags are
recorded in the decision stream but reviewed at session granularity.
"""

from __future__ import annotations

import json
import sqlite3
from collections import OrderedDict
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel

from warden.schema import Decision, ToolCallEvent
from warden.session import SessionState


class FlagRecord(BaseModel):
    id: int
    call_id: str
    session_id: str
    event: ToolCallEvent
    decision: Decision
    status: str  # pending | approved | denied
    created_at: str


class StateStore(Protocol):
    def load(self, session_id: str) -> SessionState | None: ...

    def save(self, state: SessionState) -> None: ...

    def enqueue_flag(self, event: ToolCallEvent, decision: Decision) -> int: ...

    def pending_flags(self) -> list[FlagRecord]: ...

    def get_flag(self, flag_id: int) -> FlagRecord | None: ...

    def resolve_flag(self, flag_id: int, status: str) -> None: ...

    def quarantined_sessions(self) -> list[SessionState]: ...

    def audit_event(self, action: str, detail: dict[str, object]) -> None: ...


class MemoryStore:
    """Ephemeral store: dies with the process. Default for `replay`."""

    def __init__(self) -> None:
        self._states: dict[str, SessionState] = {}
        self._flags: dict[int, FlagRecord] = {}
        self._audit: list[tuple[str, dict[str, object]]] = []
        self._next_flag_id = 1

    def load(self, session_id: str) -> SessionState | None:
        state = self._states.get(session_id)
        return state.model_copy(deep=True) if state else None

    def save(self, state: SessionState) -> None:
        self._states[state.session_id] = state.model_copy(deep=True)

    def enqueue_flag(self, event: ToolCallEvent, decision: Decision) -> int:
        flag_id = self._next_flag_id
        self._next_flag_id += 1
        self._flags[flag_id] = FlagRecord(
            id=flag_id,
            call_id=event.id,
            session_id=event.session_id,
            event=event,
            decision=decision,
            status="pending",
            created_at="",
        )
        return flag_id

    def pending_flags(self) -> list[FlagRecord]:
        return [f for f in self._flags.values() if f.status == "pending"]

    def get_flag(self, flag_id: int) -> FlagRecord | None:
        return self._flags.get(flag_id)

    def resolve_flag(self, flag_id: int, status: str) -> None:
        self._flags[flag_id] = self._flags[flag_id].model_copy(update={"status": status})

    def quarantined_sessions(self) -> list[SessionState]:
        return [s.model_copy(deep=True) for s in self._states.values() if s.quarantine]

    def audit_event(self, action: str, detail: dict[str, object]) -> None:
        self._audit.append((action, detail))


class SqliteStore:
    """Durable store: what lets a one-shot `check` honor a quarantine set by
    an earlier run, and gives `review release` an observable effect (D8)."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sessions (
              session_id TEXT PRIMARY KEY,
              state_json TEXT NOT NULL,
              updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS flags (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              call_id TEXT NOT NULL,
              session_id TEXT NOT NULL,
              event_json TEXT NOT NULL,
              decision_json TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              resolved_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL DEFAULT (datetime('now')),
              action TEXT NOT NULL,
              detail_json TEXT NOT NULL
            );
            """
        )
        self._conn.commit()

    # -- sessions --------------------------------------------------------

    def load(self, session_id: str) -> SessionState | None:
        row = self._conn.execute(
            "SELECT state_json FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return SessionState.model_validate_json(row[0]) if row else None

    def save(self, state: SessionState) -> None:
        self._conn.execute(
            "INSERT INTO sessions (session_id, state_json, updated_at)"
            " VALUES (?, ?, datetime('now'))"
            " ON CONFLICT(session_id) DO UPDATE SET"
            " state_json = excluded.state_json, updated_at = excluded.updated_at",
            (state.session_id, state.model_dump_json()),
        )
        self._conn.commit()

    def quarantined_sessions(self) -> list[SessionState]:
        rows = self._conn.execute("SELECT state_json FROM sessions").fetchall()
        states = [SessionState.model_validate_json(r[0]) for r in rows]
        return [s for s in states if s.quarantine is not None]

    # -- flags -----------------------------------------------------------

    def enqueue_flag(self, event: ToolCallEvent, decision: Decision) -> int:
        cursor = self._conn.execute(
            "INSERT INTO flags (call_id, session_id, event_json, decision_json)"
            " VALUES (?, ?, ?, ?)",
            (event.id, event.session_id, event.model_dump_json(), decision.to_json()),
        )
        self._conn.commit()
        return int(cursor.lastrowid or 0)

    def _row_to_flag(self, row: tuple[int, str, str, str, str, str, str]) -> FlagRecord:
        return FlagRecord(
            id=row[0],
            call_id=row[1],
            session_id=row[2],
            event=ToolCallEvent.model_validate_json(row[3]),
            decision=Decision.model_validate_json(row[4]),
            status=row[5],
            created_at=row[6],
        )

    _FLAG_COLS = "id, call_id, session_id, event_json, decision_json, status, created_at"

    def pending_flags(self) -> list[FlagRecord]:
        rows = self._conn.execute(
            f"SELECT {self._FLAG_COLS} FROM flags WHERE status = 'pending' ORDER BY id"
        ).fetchall()
        return [self._row_to_flag(r) for r in rows]

    def get_flag(self, flag_id: int) -> FlagRecord | None:
        row = self._conn.execute(
            f"SELECT {self._FLAG_COLS} FROM flags WHERE id = ?", (flag_id,)
        ).fetchone()
        return self._row_to_flag(row) if row else None

    def resolve_flag(self, flag_id: int, status: str) -> None:
        self._conn.execute(
            "UPDATE flags SET status = ?, resolved_at = datetime('now') WHERE id = ?",
            (status, flag_id),
        )
        self._conn.commit()

    # -- audit -----------------------------------------------------------

    def audit_event(self, action: str, detail: dict[str, object]) -> None:
        self._conn.execute(
            "INSERT INTO audit (action, detail_json) VALUES (?, ?)",
            (action, json.dumps(detail, sort_keys=True)),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


class SessionCache:
    """LRU-bounded working set over a store. A spray of unique session_ids
    cannot grow memory without bound; eviction flushes to the store, never
    discards, so no taint label or quarantine is ever lost (section 8)."""

    def __init__(self, store: StateStore, max_sessions: int = 1024) -> None:
        self._store = store
        self._max = max(1, max_sessions)
        self._cache: OrderedDict[str, SessionState] = OrderedDict()

    def get(self, session_id: str) -> SessionState:
        if session_id in self._cache:
            self._cache.move_to_end(session_id)
            return self._cache[session_id]
        state = self._store.load(session_id) or SessionState(session_id=session_id)
        self._cache[session_id] = state
        if len(self._cache) > self._max:
            _, evicted = self._cache.popitem(last=False)
            self._store.save(evicted)
        return state

    def flush(self) -> None:
        for state in self._cache.values():
            self._store.save(state)

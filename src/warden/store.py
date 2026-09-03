"""Session-state persistence (D8) and the LRU-bounded working set.

The engine never touches storage; adapters own it. SqliteStore is the real
store (one operator, one writer: limitation 7); MemoryStore backs `replay`
so demos can never pollute real state or leak quarantine between runs.
"""

from __future__ import annotations

import sqlite3
from collections import OrderedDict
from pathlib import Path
from typing import Protocol

from warden.session import SessionState


class StateStore(Protocol):
    def load(self, session_id: str) -> SessionState | None: ...

    def save(self, state: SessionState) -> None: ...


class MemoryStore:
    """Ephemeral store: dies with the process. Default for `replay`."""

    def __init__(self) -> None:
        self._states: dict[str, SessionState] = {}

    def load(self, session_id: str) -> SessionState | None:
        state = self._states.get(session_id)
        return state.model_copy(deep=True) if state else None

    def save(self, state: SessionState) -> None:
        self._states[state.session_id] = state.model_copy(deep=True)


class SqliteStore:
    """Durable store: what lets a one-shot `check` honor a quarantine set by
    an earlier run, and gives `review release` an observable effect (D8)."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(path)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions ("
            "  session_id TEXT PRIMARY KEY,"
            "  state_json TEXT NOT NULL,"
            "  updated_at TEXT NOT NULL DEFAULT (datetime('now'))"
            ")"
        )
        self._conn.commit()

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

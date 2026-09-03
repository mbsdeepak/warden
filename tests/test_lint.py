"""Reachability lint (D4/D11): dead session-layer rules must be named."""

from pathlib import Path

from warden.lint import lint_policy
from warden.policy import load_policy

FIXTURE = Path(__file__).parent / "fixtures"


def _load_inline(tmp_path: Path, text: str):  # type: ignore[no-untyped-def]
    p = tmp_path / "p.yaml"
    p.write_text(text)
    return load_policy(p)


def test_shipped_policy_is_lint_clean() -> None:
    policy = load_policy(Path(__file__).parent.parent / "policy.yaml")
    assert lint_policy(policy) == []


def test_statically_blocked_taint_source_is_flagged(tmp_path: Path) -> None:
    # The original design-review bug, reproduced on purpose: every source
    # read is blocked, so taint is dead code. The lint must say so.
    policy = _load_inline(
        tmp_path,
        """
version: 1
default_action: block
rules:
  - {id: no-secrets, tool: fs.read, match: {path: ["./secrets/**"]}, action: block}
taint:
  sources:
    - {id: dead-source, tool: fs.read, match: {path: ["./secrets/**"]}, label: x}
  sinks:
    - {id: sink, tool: http.post, when_label: x, action: block, reason: r}
""",
    )
    warnings = lint_policy(policy)
    assert len(warnings) == 1
    assert "dead-source" in warnings[0] and "unreachable" in warnings[0]


def test_unarmable_sequence_step_is_flagged(tmp_path: Path) -> None:
    # D11's bug class: no rule lets fs.write through, so the pattern never arms.
    policy = _load_inline(
        tmp_path,
        """
version: 1
default_action: block
rules:
  - {id: reads, tool: fs.read, match: {path: ["./ws/**"]}, action: allow}
  - {id: shell, tool: shell.exec, action: flag, reason: r}
sequences:
  - id: wte
    when:
      pattern:
        - {tool: fs.write, capture: path}
        - {tool: shell.exec, args_reference: path}
      within_calls: 10
    action: block
    reason: r
""",
    )
    warnings = lint_policy(policy)
    assert len(warnings) == 1
    assert "wte" in warnings[0] and "never arm" in warnings[0]

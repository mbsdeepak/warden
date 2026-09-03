"""Policy reachability lint (D4, D11).

A session-layer trigger that presupposes an *executed* call must be
executable under the static rules, or the rule is dead code in disguise:
a taint source whose every read is statically blocked can never taint, and
a capture step whose every write is blocked can never arm. The check is a
heuristic (it evaluates synthesized sample paths, not glob intersection),
which is exactly enough to catch the misconfiguration class that came up
twice in design review.
"""

from __future__ import annotations

from warden.engine import evaluate_static
from warden.policy import Policy
from warden.schema import ToolCallEvent


def _sample_path(pattern: str) -> str:
    """A concrete path that satisfies the glob it was derived from."""
    return pattern.replace("**", "x").replace("*", "x").replace("?", "x")


def _executable(policy: Policy, tool: str, path: str) -> bool:
    event = ToolCallEvent(id="lint", session_id="lint", tool=tool, args={"path": path})
    return evaluate_static(event, policy).action in ("allow", "flag")


def lint_policy(policy: Policy) -> list[str]:
    warnings: list[str] = []

    for source in policy.taint.sources:
        for pattern in source.match.path or []:
            if not _executable(policy, source.tool, _sample_path(pattern)):
                warnings.append(
                    f"taint source '{source.id}' is unreachable: {source.tool} of"
                    f" '{pattern}' is statically blocked, and blocked reads never"
                    " taint (D4). Either allow the read or delete the source."
                )

    for seq in policy.sequences:
        if seq.when.pattern is None:
            continue
        step1 = seq.when.pattern[0]
        patterns = step1.match.path if step1.match and step1.match.path else None
        if patterns is None:
            # No path constraint: reachable iff any static rule lets the tool
            # through anywhere (or the default action does).
            reachable = policy.default_action != "block" or any(
                step1.tool in rule.tools and rule.action != "block" for rule in policy.rules
            )
            if not reachable:
                warnings.append(
                    f"sequence '{seq.id}' can never arm: every {step1.tool} is"
                    " statically blocked, and blocked calls never arm a step (D11)."
                )
        else:
            for pattern in patterns:
                if not _executable(policy, step1.tool, _sample_path(pattern)):
                    warnings.append(
                        f"sequence '{seq.id}' step 1 is unreachable for pattern"
                        f" '{pattern}': {step1.tool} there is statically blocked (D11)."
                    )

    return warnings

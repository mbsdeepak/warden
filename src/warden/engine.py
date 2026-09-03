"""The decision engine: static policy layer + verdict combination.

Pure library: no I/O, no globals. The session layer (taint, sequences,
quarantine) plugs into `decide` as additional verdicts; combination
semantics are D1: first-match-wins inside the static rule list,
most-restrictive-wins (block > flag > allow) across layers.
"""

from __future__ import annotations

from dataclasses import dataclass

from warden.matchers import match_command, match_domain, match_path
from warden.policy import MatchSpec, Policy, StaticRule
from warden.schema import SEVERITY, Action, Decision, ToolCallEvent


@dataclass(frozen=True)
class Verdict:
    """One layer's opinion on one event."""

    action: Action
    rule: str  # qualified id, e.g. "static.fs-read-workspace"
    reason: str
    layer: str  # "static" | "session"
    explicit: bool  # False only for the default action
    source: str = "rule"  # "rule" | "quarantine" (D10: quarantine downgrades)


def _spec_matches(spec: MatchSpec, event: ToolCallEvent, home: str | None) -> bool:
    """Every present field must match its conventional arg. A present field
    whose arg is missing or not a string is a non-match: an fs.read with no
    path can never satisfy a path rule, so it falls through to the default
    action (fail closed) rather than being waved past a matcher it dodged.
    """
    if spec.path is not None:
        arg = event.args.get("path")
        if not isinstance(arg, str) or not match_path(arg, spec.path, home):
            return False
    if spec.domain is not None:
        arg = event.args.get("url")
        if not isinstance(arg, str) or not match_domain(arg, spec.domain):
            return False
    if spec.command is not None:
        arg = event.args.get("command")
        if not isinstance(arg, str) or not match_command(arg, spec.command, home):
            return False
    return True


def rule_matches(rule: StaticRule, event: ToolCallEvent, home: str | None) -> bool:
    if event.tool not in rule.tools:
        return False
    if rule.match is None:
        return True
    return _spec_matches(rule.match, event, home)


def evaluate_static(event: ToolCallEvent, policy: Policy) -> Verdict:
    """First match wins; no match falls to the default action."""
    for rule in policy.rules:
        if rule_matches(rule, event, policy.home):
            return Verdict(
                action=rule.action,
                rule=f"static.{rule.id}",
                reason=rule.reason or f"matched rule {rule.id}",
                layer="static",
                explicit=True,
            )
    return Verdict(
        action=policy.default_action,
        rule="static.default",
        reason=(
            f"no rule matched tool '{event.tool}'; default action is {policy.default_action}"
        ),
        layer="static",
        explicit=False,
    )


def combine(verdicts: list[Verdict]) -> Verdict:
    """Most-restrictive-wins across layers. Reason attribution among the
    winners: an explicit rule beats the default action, and a session-layer
    rule beats a static rule (its reason carries more context, e.g. the
    tainting call). All verdicts stay visible via matched_rules on the
    Decision; this tie-break only picks which reason leads.
    """
    if not verdicts:
        raise ValueError("combine() needs at least one verdict")
    top = max(SEVERITY[v.action] for v in verdicts)
    winners = [v for v in verdicts if SEVERITY[v.action] == top]
    # explicit > default; a rule's reason > the quarantine downgrade's
    # (a call flagged on its own merits stays legible as such, D10);
    # session > static (richer context, e.g. the tainting call).
    winners.sort(
        key=lambda v: (v.explicit, v.source != "quarantine", v.layer == "session"),
        reverse=True,
    )
    return winners[0]


class Engine:
    """Evaluates events against a policy. Session-layer verdicts are supplied
    by the caller (the adapter owns session state per D8); with none given,
    this is a pure per-call firewall."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def decide(
        self, event: ToolCallEvent, session_verdicts: list[Verdict] | None = None
    ) -> Decision:
        verdicts = [evaluate_static(event, self.policy)]
        if session_verdicts:
            verdicts.extend(session_verdicts)
        winner = combine(verdicts)
        flag_source: str | None = None
        if winner.action == "flag":
            # `quarantine` marks flags that exist solely because of the
            # session downgrade; any rule-flag keeps the call enqueueable (D10).
            has_rule_flag = any(
                v.action == "flag" and v.source == "rule" for v in verdicts
            )
            flag_source = "rule" if has_rule_flag else "quarantine"
        return Decision(
            id=event.id,
            session_id=event.session_id,
            decision=winner.action,
            rule=winner.rule,
            matched_rules=[v.rule for v in verdicts],
            reason=winner.reason,
            flag_source=flag_source,
        )

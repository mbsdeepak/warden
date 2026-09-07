"""The decision engine: static policy layer + verdict combination.

Pure library: no I/O, no globals. The session layer (taint, sequences,
quarantine) plugs into `decide` as additional verdicts; combination
semantics are D1: first-match-wins inside the static rule list,
most-restrictive-wins (block > flag > allow) across layers.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from warden.matchers import match_command, match_domain, match_path
from warden.policy import MatchSpec, Policy, StaticRule
from warden.schema import SEVERITY, Action, Decision, ToolCallEvent

if TYPE_CHECKING:
    from warden.overrides import Override


@dataclass(frozen=True)
class Verdict:
    """One layer's opinion on one event."""

    action: Action
    rule: str  # qualified id, e.g. "static.fs-read-workspace"
    reason: str
    layer: str  # "static" | "session"
    explicit: bool  # False only for the default action
    source: str = "rule"  # "rule" | "quarantine" (D10: quarantine downgrades)


class ArgMatcher(Protocol):
    def __call__(
        self, value: str, patterns: list[str], home: str | None, restrictive: bool
    ) -> bool: ...


def _match_path_arg(value: str, patterns: list[str], home: str | None, restrictive: bool) -> bool:
    return match_path(value, patterns, home)


def _match_domain_arg(value: str, patterns: list[str], home: str | None, restrictive: bool) -> bool:
    return match_domain(value, patterns)


def _match_command_arg(
    value: str, patterns: list[str], home: str | None, restrictive: bool
) -> bool:
    return match_command(value, patterns, home, restrictive=restrictive)


@dataclass(frozen=True)
class ArgType:
    """How one MatchSpec field is evaluated: which event arg it reads, and the
    matcher that compares that arg to the field's patterns."""

    arg: str
    match: ArgMatcher


# Registry: MatchSpec field -> argument type. Adding an argument type (say
# `sql` for a db.query tool) is a field on MatchSpec, a matcher function, and
# one entry here; nothing else in the engine or session layer changes.
# test_engine asserts the registry covers every MatchSpec field.
ARG_TYPES: dict[str, ArgType] = {
    "path": ArgType("path", _match_path_arg),
    "domain": ArgType("url", _match_domain_arg),
    "command": ArgType("command", _match_command_arg),
}


def _spec_matches(
    spec: MatchSpec, event: ToolCallEvent, home: str | None, *, restrictive: bool = False
) -> bool:
    """Every present field must match its conventional arg. A present field
    whose arg is missing or not a string is a non-match: an fs.read with no
    path can never satisfy a path rule, so it falls through to the default
    action (fail closed) rather than being waved past a matcher it dodged.

    `restrictive` says what the match is for. An allow rule is permission,
    which must cover the whole argument; a block/flag rule or a sequence step
    is restriction, which fires on any part. Only compound argument types
    (today: shell commands, split into segments) distinguish the two.
    """
    for field, arg_type in ARG_TYPES.items():
        patterns = getattr(spec, field)
        if patterns is None:
            continue
        arg = event.args.get(arg_type.arg)
        if not isinstance(arg, str) or not arg_type.match(arg, patterns, home, restrictive):
            return False
    return True


def rule_matches(rule: StaticRule, event: ToolCallEvent, home: str | None) -> bool:
    if event.tool not in rule.tools:
        return False
    if rule.match is None:
        return True
    return _spec_matches(rule.match, event, home, restrictive=rule.action != "allow")


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
        reason=(f"no rule matched tool '{event.tool}'; default action is {policy.default_action}"),
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

    def __init__(self, policy: Policy, overrides: Sequence[Override] = ()) -> None:
        self.policy = policy
        self.overrides = list(overrides)

    def _override_verdict(self, event: ToolCallEvent) -> Verdict | None:
        """Minted exceptions are evaluated before the main rule list (D6:
        under first-match-wins, position is priority) and match the exact
        tool + exact argument values, nothing wider."""
        for override in self.overrides:
            if override.tool == event.tool and override.args == event.args:
                return Verdict(
                    action="allow",
                    rule=f"override.{override.id}",
                    reason=(
                        f"exact-match exception minted from flag {override.minted_from}:"
                        f" {override.reason}"
                    ),
                    layer="static",
                    explicit=True,
                )
        return None

    def decide(
        self, event: ToolCallEvent, session_verdicts: list[Verdict] | None = None
    ) -> Decision:
        verdicts = [self._override_verdict(event) or evaluate_static(event, self.policy)]
        if session_verdicts:
            verdicts.extend(session_verdicts)
        winner = combine(verdicts)
        flag_source: str | None = None
        if winner.action == "flag":
            # `quarantine` marks flags that exist solely because of the
            # session downgrade; any rule-flag keeps the call enqueueable (D10).
            has_rule_flag = any(v.action == "flag" and v.source == "rule" for v in verdicts)
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

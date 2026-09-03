"""Policy config: models, loader, validation.

Policy lives in YAML, is validated strictly at startup (extra keys are
errors: a typo like `acton:` must refuse to start, not silently drop a
rule), and an invalid policy never yields a running firewall (DESIGN.md
section 5, section 8).
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from warden.schema import Action


class PolicyError(Exception):
    """The policy file is invalid; warden refuses to start."""


class MatchSpec(BaseModel):
    """Argument patterns; every present field must match (AND). Which event
    arg each field inspects is fixed by convention: path -> args.path,
    domain -> args.url, command -> args.command."""

    model_config = ConfigDict(extra="forbid")

    path: list[str] | None = None
    domain: list[str] | None = None
    command: list[str] | None = None

    @model_validator(mode="after")
    def at_least_one(self) -> MatchSpec:
        if self.path is None and self.domain is None and self.command is None:
            raise ValueError("match spec must name at least one of path/domain/command")
        return self


class StaticRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    tool: str | list[str]
    match: MatchSpec | None = None
    action: Action
    reason: str | None = None

    @property
    def tools(self) -> list[str]:
        return [self.tool] if isinstance(self.tool, str) else self.tool


class TaintSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    tool: str
    match: MatchSpec
    label: str = Field(min_length=1)


class TaintSink(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    tool: str | list[str]
    when_label: str
    action: Literal["block", "flag"]
    reason: str

    @property
    def tools(self) -> list[str]:
        return [self.tool] if isinstance(self.tool, str) else self.tool


class TaintConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sources: list[TaintSource] = Field(default_factory=list)
    sinks: list[TaintSink] = Field(default_factory=list)


class PatternStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str
    match: MatchSpec | None = None
    capture: Literal["path"] | None = None
    args_reference: Literal["path"] | None = None


class SequenceWhen(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_blocked: int | None = Field(default=None, ge=1)
    pattern: list[PatternStep] | None = None
    within_calls: int = Field(ge=1)

    @model_validator(mode="after")
    def exactly_one_trigger(self) -> SequenceWhen:
        if (self.min_blocked is None) == (self.pattern is None):
            raise ValueError("sequence `when` needs exactly one of min_blocked / pattern")
        if self.pattern is not None:
            # This version supports two-step capture/reference patterns
            # (write-then-execute shaped); refuse anything else loudly rather
            # than half-honoring it (documented limitation).
            if len(self.pattern) != 2:
                raise ValueError("sequence patterns must have exactly two steps")
            if self.pattern[0].capture != "path" or self.pattern[1].args_reference != "path":
                raise ValueError(
                    "step 1 must set `capture: path`; step 2 must set `args_reference: path`"
                )
        return self


class SequenceRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    when: SequenceWhen
    action: Literal["block", "flag"] | None = None
    escalate: Literal["quarantine"] | None = None
    reason: str

    @model_validator(mode="after")
    def exactly_one_effect(self) -> SequenceRule:
        # Per-call `action` when the dangerous call is the current one;
        # session `escalate` when the behavior indicts the session (D7).
        if (self.action is None) == (self.escalate is None):
            raise ValueError("sequence rule needs exactly one of action / escalate")
        return self


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: int
    default_action: Action
    home: str | None = None  # optional `~` expansion for path matching
    rules: list[StaticRule] = Field(default_factory=list)
    taint: TaintConfig = Field(default_factory=TaintConfig)
    sequences: list[SequenceRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_ids(self) -> Policy:
        seen: set[str] = set()
        for kind, rule_id in (
            [("static", r.id) for r in self.rules]
            + [("taint", s.id) for s in self.taint.sources]
            + [("taint", s.id) for s in self.taint.sinks]
            + [("seq", s.id) for s in self.sequences]
        ):
            qualified = f"{kind}.{rule_id}"
            if qualified in seen:
                raise ValueError(f"duplicate rule id: {qualified}")
            seen.add(qualified)
        return self


def load_policy(path: Path) -> Policy:
    """Load and strictly validate a policy file. Any problem raises
    PolicyError with a message naming the exact failure: warden never starts
    with a partial or guessed policy (fail closed)."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy file {path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError(f"policy file {path} must be a YAML mapping")
    try:
        return Policy.model_validate(data)
    except ValidationError as exc:
        raise PolicyError(f"policy file {path} is invalid:\n{exc}") from exc

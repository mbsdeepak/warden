"""Event and decision schemas.

The tool-call event format is defined by warden (the assignment leaves it
open); see DESIGN.md section 3. Validation is strict: a structurally valid
JSON object that violates this schema is blocked, never guessed at.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Action = Literal["allow", "block", "flag"]

# Severity order for most-restrictive-wins across layers (DESIGN.md D1).
SEVERITY: dict[str, int] = {"allow": 0, "flag": 1, "block": 2}


class ToolCallEvent(BaseModel):
    """One proposed tool call, as received from the agent runtime."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(min_length=1, max_length=256)
    session_id: str = Field(min_length=1, max_length=256)
    tool: str = Field(min_length=1, max_length=128)
    args: dict[str, Any]
    ts: str | None = None
    agent: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    """The firewall's verdict on one event (or one unparseable input line)."""

    id: str | None
    session_id: str | None
    decision: Action
    rule: str
    matched_rules: list[str]
    reason: str
    flag_source: Literal["rule", "quarantine"] | None = None

    def to_json(self) -> str:
        return self.model_dump_json(exclude_none=True)

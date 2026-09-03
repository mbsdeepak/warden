"""Minted exceptions (D6): exact-match, human-approved, evaluated first.

An override matches the exact tool and exact argument values of the approved
call, nothing wider. Close variants re-flag; that is the intended trade: a
human approved one specific call, not a pattern, and silently generalizing
their approval is how firewalls grow holes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from warden.policy import PolicyError


class Override(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    tool: str
    args: dict[str, Any]  # exact values, compared by equality
    reason: str
    minted_from: str  # the flag this was approved from
    minted_at: str


def load_overrides(path: Path) -> list[Override]:
    """Load the overrides file; a missing file is an empty list (nothing has
    been approved yet), but an *invalid* one refuses to start: silently
    dropping a reviewer's decision is worse than stopping."""
    if not path.exists():
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"overrides file {path} is unreadable: {exc}") from exc
    if data is None:
        return []
    if not isinstance(data, list):
        raise PolicyError(f"overrides file {path} must be a YAML list")
    try:
        return [Override.model_validate(item) for item in data]
    except ValidationError as exc:
        raise PolicyError(f"overrides file {path} is invalid:\n{exc}") from exc


def append_override(path: Path, override: Override) -> None:
    existing = load_overrides(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    serialized = [o.model_dump() for o in [*existing, override]]
    path.write_text(yaml.safe_dump(serialized, sort_keys=False), encoding="utf-8")

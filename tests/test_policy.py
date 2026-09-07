"""Policy loading: valid config loads; anything invalid refuses to start."""

from pathlib import Path

import pytest

from warden.policy import PolicyError, load_policy

REPO_POLICY = Path(__file__).parent.parent / "policy.yaml"


def _write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(text)
    return p


def test_repo_example_policy_loads() -> None:
    policy = load_policy(REPO_POLICY)
    assert policy.default_action == "block"
    # Never-readable secrets come first so no allow glob can shadow them (D14).
    assert [r.id for r in policy.rules][0] == "fs-read-secrets"
    assert len(policy.rules) == 9
    assert policy.taint.sources[0].label == "pii"
    assert policy.sequences[0].escalate == "quarantine"


def test_missing_file_refuses(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="cannot read"):
        load_policy(tmp_path / "nope.yaml")


def test_invalid_yaml_refuses(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not valid YAML"):
        load_policy(_write(tmp_path, "rules: [unclosed"))


def test_typo_field_refuses(tmp_path: Path) -> None:
    # `acton` instead of `action`: must refuse, never silently drop the rule.
    with pytest.raises(PolicyError, match="invalid"):
        load_policy(
            _write(
                tmp_path,
                "version: 1\ndefault_action: block\n"
                "rules:\n  - {id: r1, tool: fs.read, acton: allow}\n",
            )
        )


def test_bad_action_refuses(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="invalid"):
        load_policy(
            _write(
                tmp_path,
                "version: 1\ndefault_action: block\n"
                "rules:\n  - {id: r1, tool: fs.read, action: permit}\n",
            )
        )


def test_duplicate_rule_id_refuses(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="duplicate rule id"):
        load_policy(
            _write(
                tmp_path,
                "version: 1\ndefault_action: block\n"
                "rules:\n"
                "  - {id: r1, tool: fs.read, action: allow}\n"
                "  - {id: r1, tool: fs.list, action: allow}\n",
            )
        )


def test_sequence_needs_exactly_one_effect(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="invalid"):
        load_policy(
            _write(
                tmp_path,
                "version: 1\ndefault_action: block\n"
                "sequences:\n"
                "  - id: s1\n"
                "    when: {min_blocked: 3, within_calls: 10}\n"
                "    action: flag\n"
                "    escalate: quarantine\n"
                "    reason: x\n",
            )
        )


def test_default_action_allow_is_expressible_but_explicit(tmp_path: Path) -> None:
    # An allow-by-default policy is legal (the operator's choice), never implied.
    policy = load_policy(_write(tmp_path, "version: 1\ndefault_action: allow\n"))
    assert policy.default_action == "allow"

"""Configuration loading for federated-agent-audit.

Supports JSON and YAML policy files so teams can version-control
their privacy policies alongside code.

Usage:
    # JSON
    policy = load_policy("policies/hr_bot.json")

    # YAML
    policy = load_policy("policies/hr_bot.yaml")

    # From dict
    policy = load_policy({"agent_id": "hr_bot", "must_not_share": ["email"]})

    # Multiple policies
    policies = load_policies_dir("policies/")

Example YAML policy (hr_bot.yaml):

    agent_id: hr_bot
    must_not_share:
      - salary
      - SSN
      - performance review
    acceptable_abstractions:
      salary: compensation level
      SSN: employee identifier
    sensitivity_threshold: 3
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Union

from .schemas import PrivacyPolicy

logger = logging.getLogger(__name__)


def load_policy(source: Union[str, Path, dict]) -> PrivacyPolicy:
    """Load a PrivacyPolicy from a file path or dict.

    Supported formats: .json, .yaml, .yml, or a Python dict.
    """
    if isinstance(source, dict):
        return PrivacyPolicy(**source)

    path = Path(source)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()

    if suffix == ".json":
        data = json.loads(text)
    elif suffix in (".yaml", ".yml"):
        data = _load_yaml(text)
    else:
        raise ValueError(f"Unsupported policy file format: {suffix} (use .json or .yaml)")

    logger.info("Loaded policy for agent '%s' from %s", data.get("agent_id", "?"), path)
    return PrivacyPolicy(**data)


def load_policies_dir(directory: Union[str, Path]) -> list[PrivacyPolicy]:
    """Load all policy files from a directory.

    Scans for .json, .yaml, .yml files and loads each as a PrivacyPolicy.
    """
    dirpath = Path(directory)
    if not dirpath.is_dir():
        raise NotADirectoryError(f"Not a directory: {dirpath}")

    policies = []
    for ext in ("*.json", "*.yaml", "*.yml"):
        for filepath in sorted(dirpath.glob(ext)):
            try:
                policies.append(load_policy(filepath))
                logger.info("Loaded policy: %s", filepath.name)
            except Exception as e:
                logger.warning("Skipped %s: %s", filepath.name, e)

    return policies


def validate_policy(source: Union[str, Path, dict]) -> list[str]:
    """Validate a policy file and return a list of warnings.

    Returns empty list if the policy is valid.
    """
    warnings: list[str] = []

    try:
        policy = load_policy(source)
    except Exception as e:
        return [f"Invalid policy: {e}"]

    if not policy.agent_id:
        warnings.append("agent_id is empty")

    if not policy.must_not_share:
        warnings.append("must_not_share is empty — policy blocks nothing")

    if policy.sensitivity_threshold < 1:
        warnings.append("sensitivity_threshold < 1 — everything will be blocked")
    elif policy.sensitivity_threshold > 5:
        warnings.append("sensitivity_threshold > 5 — nothing will be blocked by threshold")

    for term in policy.must_not_share:
        if len(term) < 2:
            warnings.append(f"Short blocklist term '{term}' may cause false positives")

    for raw, abstract in policy.acceptable_abstractions.items():
        if raw not in policy.must_not_share:
            warnings.append(
                f"Abstraction '{raw}' -> '{abstract}' has no matching must_not_share rule"
            )

    return warnings


def policy_to_dict(policy: PrivacyPolicy) -> dict:
    """Serialize a policy to a plain dict (for saving to JSON/YAML)."""
    return policy.model_dump(exclude={"policy_id"})


def save_policy(policy: PrivacyPolicy, path: Union[str, Path]) -> None:
    """Save a policy to a JSON or YAML file."""
    filepath = Path(path)
    data = policy_to_dict(policy)

    if filepath.suffix.lower() in (".yaml", ".yml"):
        yaml = _get_yaml()
        filepath.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False),
                           encoding="utf-8")
    else:
        filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8")

    logger.info("Saved policy for '%s' to %s", policy.agent_id, filepath)


def _load_yaml(text: str) -> dict:
    """Load YAML text, with a clear error if pyyaml is missing."""
    yaml = _get_yaml()
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("YAML file must contain a mapping at top level")
    return data


def _get_yaml():
    """Import yaml with a helpful error message."""
    try:
        import yaml
        return yaml
    except ImportError:
        raise ImportError(
            "PyYAML is required for YAML policy files. "
            "Install it with: pip install 'federated-agent-audit[yaml]'"
        )

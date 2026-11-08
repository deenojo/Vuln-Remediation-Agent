"""Deterministic policy gate. Plain code, no model: given a proposed fix and its triage,
decide AUTO_MERGE, HUMAN_REVIEW or SKIP and record every reason.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import yaml
from packaging.version import InvalidVersion, Version


class Decision(str, Enum):
    AUTO_MERGE = "auto_merge"
    HUMAN_REVIEW = "human_review"
    SKIP = "skip"


@dataclass
class GateResult:
    decision: Decision
    change_type: str
    reasons: list[str] = field(default_factory=list)


def load_policy(path: str | Path = "policy/policy.yaml") -> dict:
    return yaml.safe_load(Path(path).read_text())


def classify_bump(installed: str, fixed: str, ecosystem: str) -> str:
    """'patch' | 'minor' | 'major' for language packages, 'os_patch' for OS packages."""
    if ecosystem not in ("PyPI", "npm", "Go", "crates.io"):
        return "os_patch"
    try:
        a, b = Version(installed), Version(fixed)
    except InvalidVersion:
        return "major"  # unknown shape: treat as the riskiest kind
    a_rel = (list(a.release) + [0, 0, 0])[:3]
    b_rel = (list(b.release) + [0, 0, 0])[:3]
    if b_rel[0] != a_rel[0]:
        return "major"
    if b_rel[1] != a_rel[1]:
        return "minor"
    return "patch"


def evaluate(
    *,
    package: str,
    installed: str,
    fixed: str | None,
    ecosystem: str,
    recommendation: str,
    risk_score: int,
    confidence: float,
    policy: dict,
) -> GateResult:
    if not fixed:
        return GateResult(Decision.SKIP, "none", ["no fixed version available"])
    change = classify_bump(installed, fixed, ecosystem)
    reasons: list[str] = [f"{change} bump {installed} -> {fixed}"]
    review = False

    if os.environ.get("VRA_AUTOMERGE_DISABLED") == "1" or not policy.get("auto_merge_enabled", False):
        reasons.append("kill switch: auto-merge disabled")
        review = True
    if recommendation in policy.get("never_auto_merge_recommendations", []):
        reasons.append(f"recommendation '{recommendation}' never auto-merges")
        review = True
    if package.lower() in {p.lower() for p in policy.get("always_review_packages", [])}:
        reasons.append(f"'{package}' is on the always-review list")
        review = True
    rule = (policy.get("auto_merge") or {}).get(change, {})
    if not rule.get("allowed", False):
        reasons.append(f"{change} bumps require human review")
        review = True
    elif risk_score < rule.get("min_risk_score", 101):
        reasons.append(f"risk {risk_score} below auto-merge threshold {rule.get('min_risk_score')}")
        review = True
    if confidence < policy.get("min_confidence_for_auto_merge", 1.0):
        reasons.append(f"triage confidence {confidence:.2f} below threshold")
        review = True

    if not review:
        reasons.append("all auto-merge conditions met (still requires passing tests)")
    return GateResult(Decision.HUMAN_REVIEW if review else Decision.AUTO_MERGE, change, reasons)

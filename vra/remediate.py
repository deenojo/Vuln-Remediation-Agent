"""Turn triaged findings into fix plans, apply them, and (optionally) open PRs.

One PR per (manifest, package): small diffs that are easy to review and easy to revert.
Hard rule: remediation may only edit dependency manifests. It refuses to touch policy/,
.github/ or anything else, so a confused or manipulated agent can't loosen its own rules.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from packaging.version import InvalidVersion, Version

from vra.models import Finding
from vra.policy import Decision, GateResult, evaluate

ALLOWED_MANIFEST = re.compile(r"(^|/)requirements[\w.-]*\.txt$")
FORBIDDEN_PREFIXES = ("policy/", ".github/")


class ForbiddenPathError(Exception):
    pass


@dataclass
class FixPlan:
    manifest: str
    package: str
    installed: str
    target_version: str
    vuln_ids: list[str]
    risk_score: int
    recommendation: str
    confidence: float
    rationale: str
    gate: GateResult
    finding_keys: list[str] = field(default_factory=list)

    @property
    def branch(self) -> str:
        return f"vra/fix-{self.package.lower()}-{self.target_version}"

    @property
    def label(self) -> str:
        return "vra:auto-merge" if self.gate.decision is Decision.AUTO_MERGE else "vra:needs-review"


def _vkey(v: str):
    try:
        return (1, Version(v))
    except InvalidVersion:
        return (0, v)


def check_path(manifest: str) -> None:
    p = str(PurePosixPath(manifest.replace("\\", "/")))
    if ".." in PurePosixPath(p).parts or p.startswith("/"):
        raise ForbiddenPathError(f"refusing path outside the repo: {manifest}")
    if p.startswith(FORBIDDEN_PREFIXES) or not ALLOWED_MANIFEST.search(p):
        raise ForbiddenPathError(f"remediation may only edit requirements files, not {manifest}")


def build_plans(findings: list[Finding], triage: dict, policy: dict) -> list[FixPlan]:
    """Group fixable PyPI repo findings by (manifest, package) and run each through the gate."""
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        if f.target_type == "repo" and f.ecosystem == "PyPI" and f.fixed_version:
            groups.setdefault((f.target, f.package.lower()), []).append(f)
    plans = []
    for (manifest, _), group in sorted(groups.items()):
        group.sort(key=lambda f: len(f.installed_version))  # prefer the spelling used in the file
        target = max((f.fixed_version for f in group), key=_vkey)  # one bump fixes all
        tri = [triage[f.dedupe_key] for f in group if f.dedupe_key in triage]
        if not tri:
            continue  # never act on untriaged findings
        worst = max(tri, key=lambda t: t["risk_score"])
        conf = min(t["confidence"] for t in tri)
        gate = evaluate(
            package=group[0].package, installed=group[0].installed_version, fixed=target,
            ecosystem="PyPI", recommendation=worst["recommendation"],
            risk_score=worst["risk_score"], confidence=conf, policy=policy,
        )
        if gate.decision is Decision.SKIP:
            continue
        plans.append(
            FixPlan(
                manifest=manifest, package=group[0].package, installed=group[0].installed_version,
                target_version=target, vuln_ids=sorted({f.vuln_id for f in group}),
                risk_score=worst["risk_score"], recommendation=worst["recommendation"],
                confidence=conf, rationale=worst["rationale"], gate=gate,
                finding_keys=[f.dedupe_key for f in group],
            )
        )
    return sorted(plans, key=lambda p: -p.risk_score)


def apply_plan(plan: FixPlan, repo_root: str | Path = ".") -> bool:
    """Rewrite the pin in the manifest. Returns True if the file changed."""
    check_path(plan.manifest)
    path = Path(repo_root) / plan.manifest
    text = path.read_text()
    pattern = re.compile(
        rf"^(\s*{re.escape(plan.package)}\s*==\s*)([^\s#;]+)", flags=re.I | re.M
    )
    new_text, n = pattern.subn(lambda m: m.group(1) + plan.target_version, text)
    if n == 0 or new_text == text:
        return False
    path.write_text(new_text)
    return True


def pr_title(plan: FixPlan) -> str:
    ids = plan.vuln_ids[:2] + ([f"+{len(plan.vuln_ids) - 2} more"] if len(plan.vuln_ids) > 2 else [])
    return f"fix(deps): bump {plan.package} {plan.installed} -> {plan.target_version} ({', '.join(ids)})"


def pr_body(plan: FixPlan) -> str:
    reasons = "\n".join(f"- {r}" for r in plan.gate.reasons)
    return f"""## Automated vulnerability fix

| | |
|---|---|
| Package | `{plan.package}` `{plan.installed}` → `{plan.target_version}` |
| Fixes | {len(plan.vuln_ids)} advisories: {', '.join(plan.vuln_ids)} |
| Manifest | `{plan.manifest}` |
| Risk score | {plan.risk_score}/100 ({plan.recommendation}, confidence {plan.confidence:.2f}) |
| Policy decision | **{plan.gate.decision.value}** ({plan.gate.change_type}) |

### Why (triage)
{plan.rationale}

### Policy gate
{reasons}

---
*Opened by Patchwarden. Merges only after required checks pass. The agent recommends; `policy/policy.yaml` decides.*
"""


def _git(*args: str, cwd: str | Path = ".") -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def commit_on_branch(plan: FixPlan, repo_root: str | Path = ".", base: str = "main") -> bool:
    _git("checkout", "-B", plan.branch, base, cwd=repo_root)
    changed = apply_plan(plan, repo_root)
    if changed:
        _git("add", plan.manifest, cwd=repo_root)
        _git("commit", "-m", pr_title(plan), cwd=repo_root)
    _git("checkout", base, cwd=repo_root)
    if not changed:  # e.g. a transitive dependency with no pin to bump: don't leave an empty branch
        _git("branch", "-D", plan.branch, cwd=repo_root)
    return changed


def open_pr(plan: FixPlan, repo: str, token: str, base: str = "main") -> dict:
    """Create the PR through the GitHub REST API and label it with the gate's decision."""
    api = f"https://api.github.com/repos/{repo}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    def call(method: str, url: str, payload: dict) -> dict:
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"{}")

    pr = call("POST", f"{api}/pulls", {
        "title": pr_title(plan), "head": plan.branch, "base": base, "body": pr_body(plan),
    })
    call("POST", f"{api}/issues/{pr['number']}/labels", {"labels": [plan.label]})
    return pr


def github_context() -> tuple[str | None, str | None]:
    return os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_TOKEN")

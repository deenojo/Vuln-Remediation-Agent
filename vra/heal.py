"""Container self-healing: patch OS CVEs in an image without rebuilding it, prove the fix,
sign it, and (optionally) roll it out with automatic rollback.

  scan (trivy, OS pkgs, fixable only)
    -> policy gate (os_patch rule)
    -> copa patch            (Copacetic: adds a patch layer, no Dockerfile rebuild)
    -> re-scan + verify      (targeted CVEs gone, no new Critical/High)
    -> cosign sign           (keyless in CI)
    -> kubectl rollout       (rollback on failed rollout)

External tools are called through a Runner so the orchestration logic is unit-testable.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from vra.models import Severity
from vra.parsers import parse_trivy

Runner = Callable[[list[str]], subprocess.CompletedProcess]


def default_runner(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


# ----------------------------------------------------------------- verification (pure)

@dataclass
class Verification:
    passed: bool
    fixed: list[str] = field(default_factory=list)
    still_present: list[str] = field(default_factory=list)
    introduced: list[str] = field(default_factory=list)
    before_count: int = 0
    after_count: int = 0
    reasons: list[str] = field(default_factory=list)


def _fixable_os(report: dict) -> set[tuple[str, str]]:
    return {
        (f.vuln_id, f.package)
        for f in parse_trivy(report, target_type="image")
        if f.ecosystem not in ("PyPI", "npm", "Go", "crates.io") and f.fixable
    }


def _all(report: dict) -> dict[tuple[str, str], Severity]:
    return {(f.vuln_id, f.package): f.severity for f in parse_trivy(report, target_type="image")}


def verify(before: dict, after: dict) -> Verification:
    """A patch passes only if every fixable OS finding is gone and nothing serious appeared."""
    targeted = _fixable_os(before)
    before_all, after_all = _all(before), _all(after)
    fixed = sorted(f"{v} ({p})" for v, p in targeted if (v, p) not in after_all)
    still = sorted(f"{v} ({p})" for v, p in targeted if (v, p) in after_all)
    introduced = sorted(
        f"{v} ({p}) {s.value}"
        for (v, p), s in after_all.items()
        if (v, p) not in before_all and s.rank >= Severity.HIGH.rank
    )
    reasons = []
    if still:
        reasons.append(f"{len(still)} targeted OS CVEs still present")
    if introduced:
        reasons.append(f"{len(introduced)} new High/Critical findings introduced by the patch")
    if not targeted:
        reasons.append("nothing fixable to patch")
    passed = bool(targeted) and not still and not introduced
    if passed:
        reasons.append(f"all {len(fixed)} targeted OS CVEs fixed; no new High/Critical")
    return Verification(passed, fixed, still, introduced, len(before_all), len(after_all), reasons)


# ----------------------------------------------------------------- orchestration

@dataclass
class HealResult:
    image: str
    patched_image: str | None = None
    verification: Verification | None = None
    signed: bool = False
    deployed: bool = False
    rolled_back: bool = False
    steps: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.verification and self.verification.passed)


def _run(runner: Runner, cmd: list[str], result: HealResult, step: str) -> subprocess.CompletedProcess:
    proc = runner(cmd)
    if proc.returncode == 0:
        result.steps.append(f"{step}: ok")
    else:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
        result.steps.append(f"{step}: exit {proc.returncode}" + (f" | {' / '.join(err)[:400]}" if err else ""))
    return proc


def trivy_os_scan(runner: Runner, image: str, out: Path, result: HealResult, step: str) -> dict:
    proc = _run(runner, [
        "trivy", "image", "--scanners", "vuln", "--pkg-types", "os", "--ignore-unfixed",
        "--format", "json", "--output", str(out), image,
    ], result, step)
    if proc.returncode != 0:
        raise RuntimeError(f"trivy failed on {image}: {proc.stderr[-500:]}")
    return json.loads(out.read_text())


def heal_image(
    image: str,
    *,
    workdir: str | Path = "reports",
    patched_tag: str | None = None,
    buildkit_addr: str | None = None,
    push: bool = False,
    sign: bool = False,
    deployment: str | None = None,
    container: str = "app",
    kind_cluster: str | None = None,
    runner: Runner = default_runner,
) -> HealResult:
    work = Path(workdir)
    work.mkdir(parents=True, exist_ok=True)
    result = HealResult(image=image)
    repo, _, tag = image.rpartition(":") if ":" in image.split("/")[-1] else (image, "", "latest")
    patched = f"{repo}:{patched_tag or (tag + '-patched')}"

    before = trivy_os_scan(runner, image, work / "heal-before.json", result, "scan before")
    if not _fixable_os(before):
        result.verification = verify(before, before)
        result.steps.append("nothing fixable: skipped patch")
        return result

    copa = ["copa", "patch", "-i", image, "-r", str(work / "heal-before.json"), "-t", patched.rpartition(":")[2]]
    if buildkit_addr:
        copa += ["--addr", buildkit_addr]
    if _run(runner, copa, result, "copa patch").returncode != 0:
        result.verification = Verification(False, reasons=["copa patch failed"])
        return result
    result.patched_image = patched

    after = trivy_os_scan(runner, patched, work / "heal-after.json", result, "scan after")
    result.verification = verify(before, after)
    if not result.verification.passed:
        return result  # never sign or deploy an unverified image

    if push and _run(runner, ["docker", "push", patched], result, "docker push").returncode != 0:
        return result

    if sign:
        result.signed = _run(runner, ["cosign", "sign", "--yes", patched], result, "cosign sign").returncode == 0
        if not result.signed:
            return result  # unsigned images don't ship

    if deployment:
        if kind_cluster:  # local kind cluster: load the image instead of pulling from a registry
            _run(runner, ["kind", "load", "docker-image", patched, "--name", kind_cluster], result, "kind load")
        _run(runner, ["kubectl", "set", "image", f"deployment/{deployment}", f"{container}={patched}"],
             result, "kubectl set image")
        rollout = _run(runner, ["kubectl", "rollout", "status", f"deployment/{deployment}", "--timeout=120s"],
                       result, "rollout status")
        if rollout.returncode == 0:
            result.deployed = True
        else:
            _run(runner, ["kubectl", "rollout", "undo", f"deployment/{deployment}"], result, "rollback")
            result.rolled_back = True
    return result

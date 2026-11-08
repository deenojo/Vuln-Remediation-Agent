"""Parse `trivy ... --format json` output (filesystem/repo or image scans)."""

from __future__ import annotations

from typing import Any

from vra.models import Finding, Severity, canonical_id

# Trivy result "Type" -> OSV-style ecosystem name
_ECOSYSTEMS = {
    "pip": "PyPI",
    "pipenv": "PyPI",
    "poetry": "PyPI",
    "npm": "npm",
    "yarn": "npm",
    "pnpm": "npm",
    "gomod": "Go",
    "cargo": "crates.io",
    "debian": "debian",
    "ubuntu": "ubuntu",
    "alpine": "alpine",
}


def _best_cvss(vuln: dict[str, Any]) -> float | None:
    scores = []
    for vendor in (vuln.get("CVSS") or {}).values():
        score = vendor.get("V3Score") or vendor.get("V2Score")
        if score is not None:
            scores.append(float(score))
    return max(scores) if scores else None


def parse_trivy(report: dict[str, Any], target_type: str) -> list[Finding]:
    """Turn a Trivy JSON report into normalized findings.

    target_type: 'repo' for `trivy fs`, 'image' for `trivy image`.
    """
    artifact = report.get("ArtifactName", "unknown")
    findings: list[Finding] = []
    for result in report.get("Results") or []:
        ecosystem = _ECOSYSTEMS.get(result.get("Type", ""), result.get("Type", "unknown"))
        # For images, the image name is the meaningful target; for repos, the manifest path.
        target = artifact if target_type == "image" else result.get("Target", artifact)
        for vuln in result.get("Vulnerabilities") or []:
            primary = vuln.get("VulnerabilityID", "")
            aliases = [a for a in vuln.get("VendorIDs") or [] if a != primary]
            cvss = _best_cvss(vuln)
            findings.append(
                Finding(
                    vuln_id=canonical_id(primary, aliases),
                    aliases=sorted({primary, *aliases} - {canonical_id(primary, aliases)}),
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion") or None,
                    ecosystem=ecosystem,
                    target=target,
                    target_type=target_type,
                    severity=Severity.parse(vuln.get("Severity")),
                    cvss=cvss,
                    title=vuln.get("Title", "") or "",
                    url=vuln.get("PrimaryURL"),
                    sources=["trivy"],
                )
            )
    return findings

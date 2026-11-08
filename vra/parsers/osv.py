"""Parse `osv-scanner --format json` output."""

from __future__ import annotations

from typing import Any

from vra.models import Finding, Severity, canonical_id


def _fixed_version(vuln: dict[str, Any], package: str) -> str | None:
    """First 'fixed' event in the affected range for this package, if any."""
    for affected in vuln.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name")
        if pkg and pkg.lower() != package.lower():
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    return event["fixed"]
    return None


def _group_score(package_entry: dict[str, Any], vuln_id: str) -> float | None:
    for group in package_entry.get("groups") or []:
        if vuln_id in (group.get("ids") or []):
            try:
                return float(group.get("max_severity"))
            except (TypeError, ValueError):
                return None
    return None


def parse_osv(report: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in report.get("results") or []:
        target = (result.get("source") or {}).get("path", "unknown")
        for entry in result.get("packages") or []:
            pkg = entry.get("package") or {}
            name, version = pkg.get("name", ""), pkg.get("version", "")
            for vuln in entry.get("vulnerabilities") or []:
                primary = vuln.get("id", "")
                aliases = vuln.get("aliases") or []
                cid = canonical_id(primary, aliases)
                score = _group_score(entry, primary)
                label = (vuln.get("database_specific") or {}).get("severity")
                severity = Severity.parse(label)
                if severity is Severity.UNKNOWN:
                    severity = Severity.from_cvss(score)
                findings.append(
                    Finding(
                        vuln_id=cid,
                        aliases=sorted({primary, *aliases} - {cid}),
                        package=name,
                        installed_version=version,
                        fixed_version=_fixed_version(vuln, name),
                        ecosystem=pkg.get("ecosystem", "unknown"),
                        target=target,
                        target_type="repo",
                        severity=severity,
                        cvss=score,
                        title=vuln.get("summary", "") or "",
                        url=f"https://osv.dev/vulnerability/{primary}" if primary else None,
                        sources=["osv-scanner"],
                    )
                )
    return findings

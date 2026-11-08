"""Merge findings from multiple scanners into one deduplicated list."""

from __future__ import annotations

from vra.models import Finding, Severity


def normalize_target(target: str, root: str | None = None) -> str:
    """Scanners report paths differently (Trivy: relative, osv-scanner: absolute).

    Make repo targets comparable: posix slashes, relative to `root`, no leading './'.
    """
    t = target.replace("\\", "/")
    if root:
        r = root.replace("\\", "/").rstrip("/") + "/"
        if t.startswith(r):
            t = t[len(r):]
    return t[2:] if t.startswith("./") else t


def merge_fix_lists(a: str | None, b: str | None) -> str | None:
    """Union of comma-separated fixed-version lists from different scanners."""
    out: list[str] = []
    for part in ",".join(x for x in (a, b) if x).split(","):
        v = part.strip()
        if v and v not in out:
            out.append(v)
    return ", ".join(out) or None


def merge_findings(findings: list[Finding], root: str | None = None) -> list[Finding]:
    """Collapse duplicates (same vuln, package, version, target) reported by different scanners.

    When scanners disagree we keep the most informative value:
    highest severity, highest CVSS, any known fixed version, union of sources and aliases.
    """
    merged: dict[str, Finding] = {}
    for f in findings:
        if f.target_type == "repo":
            f = f.model_copy(update={"target": normalize_target(f.target, root)})
        key = f.dedupe_key
        if key not in merged:
            merged[key] = f.model_copy(deep=True)
            continue
        m = merged[key]
        if f.severity.rank > m.severity.rank:
            m.severity = f.severity
        if f.cvss is not None and (m.cvss is None or f.cvss > m.cvss):
            m.cvss = f.cvss
        m.fixed_version = merge_fix_lists(m.fixed_version, f.fixed_version)
        m.title = m.title or f.title
        m.url = m.url or f.url
        m.sources = sorted(set(m.sources) | set(f.sources))
        m.aliases = sorted(set(m.aliases) | set(f.aliases))
    return sorted(
        merged.values(),
        key=lambda x: (-x.severity.rank, -(x.cvss or 0), x.target, x.package),
    )


def summarize(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    counts["TOTAL"] = len(findings)
    counts["FIXABLE"] = sum(1 for f in findings if f.fixable)
    return counts

"""Core data model: one normalized vulnerability finding, regardless of which scanner found it."""

from __future__ import annotations

import hashlib
from enum import Enum

from packaging.utils import canonicalize_version
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}[self.value]

    @classmethod
    def parse(cls, raw: str | None) -> "Severity":
        if not raw:
            return cls.UNKNOWN
        raw = raw.strip().upper()
        if raw == "MODERATE":  # GitHub advisories use MODERATE
            return cls.MEDIUM
        try:
            return cls(raw)
        except ValueError:
            return cls.UNKNOWN

    @classmethod
    def from_cvss(cls, score: float | None) -> "Severity":
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0:
            return cls.LOW
        return cls.UNKNOWN


class Finding(BaseModel):
    """A single vulnerable package in a single target (repo manifest or container image)."""

    vuln_id: str = Field(description="Canonical ID: CVE if known, else GHSA/OSV ID")
    aliases: list[str] = Field(default_factory=list)
    package: str
    installed_version: str
    fixed_version: str | None = None
    ecosystem: str = Field(description="e.g. PyPI, npm, debian, alpine")
    target: str = Field(description="Repo manifest path or image reference")
    target_type: str = Field(description="'repo' or 'image'")
    severity: Severity = Severity.UNKNOWN
    cvss: float | None = None
    title: str = ""
    url: str | None = None
    sources: list[str] = Field(default_factory=list, description="Scanners that reported it")

    @property
    def dedupe_key(self) -> str:
        """Same vuln + same package/version + same target = same finding, whichever scanner saw it."""
        raw = "|".join(
            [self.vuln_id.upper(), self.package.lower(), self.norm_version, self.target]
        )
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def norm_version(self) -> str:
        """Scanners spell the same version differently ('2.10' vs '2.10.0'); canonicalize for PyPI."""
        if self.ecosystem == "PyPI":
            try:
                return canonicalize_version(self.installed_version)
            except Exception:
                return self.installed_version
        return self.installed_version

    @property
    def fixable(self) -> bool:
        return bool(self.fixed_version)


def canonical_id(primary: str, aliases: list[str]) -> str:
    """Prefer a CVE ID so Trivy (CVE-first) and OSV (GHSA-first) findings line up."""
    for candidate in [primary, *aliases]:
        if candidate and candidate.upper().startswith("CVE-"):
            return candidate.upper()
    return primary

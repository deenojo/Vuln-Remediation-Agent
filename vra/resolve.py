"""Choose the *smallest safe* upgrade for a vulnerable pin instead of the newest one.

Why: bumping to the newest version that fixes every advisory often means a major upgrade that
breaks the build (first live run: 5 of 6 such PRs failed CI). Instead:

  1. For each advisory, find its minimal fixed version above what's installed (backports count).
  2. Prefer fixing the *urgent* advisories within the current major version.
  3. Among real releases at or above that need, pick the smallest one that is compatible:
     - its Requires-Python accepts the app's runtime (read from the Dockerfile), and
     - none of its requirements conflict with other pins in the same manifest.
  4. Advisories that can only be fixed by a major upgrade are reported as "remaining" for a
     separate human decision instead of being silently bundled in.

Package metadata comes from the PyPI JSON API through an injectable fetcher, so tests run offline
and the resolver degrades to "unverified" (never crashes) without network.
"""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

Meta = dict  # {"requires_python": str|None, "requires_dist": list[str]}
Fetcher = Callable[[str, str | None], dict | None]

URGENT = {"fix_now", "fix_soon"}


def _v(s: str) -> Version | None:
    try:
        return Version(s.strip())
    except (InvalidVersion, AttributeError):
        return None


def fix_candidates(fixed: str | None) -> list[Version]:
    return sorted({v for v in (_v(x) for x in (fixed or "").split(",")) if v})


def min_fix(installed: str, fixed: str | None) -> Version | None:
    """Smallest fixed version above the installed one (e.g. a backport in the same line)."""
    cur = _v(installed)
    for c in fix_candidates(fixed):
        if cur is None or c > cur:
            return c
    return None


def pypi_fetcher(package: str, version: str | None) -> dict | None:
    """GET https://pypi.org/pypi/<pkg>[/<version>]/json. Returns None on any failure."""
    url = f"https://pypi.org/pypi/{package}/json" if version is None else f"https://pypi.org/pypi/{package}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return json.loads(r.read())
    except Exception:
        return None


def runtime_python(manifest: str, repo_root: str | Path = ".") -> str | None:
    """Read 'FROM python:3.9...' from a Dockerfile next to the manifest."""
    dockerfile = Path(repo_root) / Path(manifest).parent / "Dockerfile"
    if not dockerfile.exists():
        return None
    m = re.search(r"^\s*FROM\s+(?:\S+/)?python:(\d+\.\d+)", dockerfile.read_text(), re.M | re.I)
    return m.group(1) if m else None


def manifest_pins(manifest: str, repo_root: str | Path = ".") -> dict[str, Version]:
    pins: dict[str, Version] = {}
    path = Path(repo_root) / manifest
    if not path.exists():
        return pins
    for line in path.read_text().splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s#;]+)", line)
        if m and _v(m.group(2)):
            pins[canonicalize_name(m.group(1))] = _v(m.group(2))
    return pins


@dataclass
class Choice:
    version: str
    fixes: list[str]
    remaining: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    verified: bool = False
    blocked: bool = False


def _compatible(package: str, version: Version, py: str | None, pins: dict[str, Version],
                fetch: Fetcher) -> tuple[bool | None, str]:
    """True/False if we could check, None if metadata was unavailable."""
    data = fetch(package, str(version))
    if not data:
        return None, "metadata unavailable"
    info = data.get("info") or {}
    rp = info.get("requires_python")
    if py and rp:
        try:
            if not SpecifierSet(rp).contains(Version(py), prereleases=True):
                return False, f"{package} {version} requires Python {rp} (app runs {py})"
        except InvalidSpecifier:
            pass
    env = {"python_version": py or "3.12", "extra": ""}
    for raw in info.get("requires_dist") or []:
        try:
            req = Requirement(raw)
        except InvalidRequirement:
            continue
        if req.marker and not req.marker.evaluate(env):
            continue
        pinned = pins.get(canonicalize_name(req.name))
        if pinned is not None and req.specifier and not req.specifier.contains(pinned, prereleases=True):
            return False, f"{package} {version} needs {req.name}{req.specifier}, but the file pins {pinned}"
    return True, "compatible"


def _pick(package, floor, ceiling_major, py, pins, fetch, max_tries, notes):
    """Smallest compatible release >= floor. Returns (version|None, verified, definitely_blocked)."""
    candidates = [floor]
    if fetch:
        meta = fetch(package, None)
        if meta and meta.get("releases"):
            rel = sorted(
                v for v in (_v(x) for x, files in meta["releases"].items() if files)
                if v and not v.is_prerelease and v >= floor
                and (ceiling_major is None or v.major == ceiling_major)
            )
            candidates = rel or candidates
    if not fetch:
        return floor, False, False
    for v in candidates[:max_tries]:
        ok, why = _compatible(package, v, py, pins, fetch)
        if ok:
            return v, True, False
        if ok is None:
            notes.append(f"compatibility of {v} unverified ({why})")
            return v, False, False
        notes.append(why)
    return None, False, True


def choose(
    package: str,
    installed: str,
    advisories: list[tuple[str, str | None, str]],  # (vuln_id, fixed_version list, recommendation)
    *,
    py: str | None = None,
    pins: dict[str, Version] | None = None,
    fetch: Fetcher | None = None,
    max_tries: int = 15,
) -> Choice | None:
    cur = _v(installed)
    pins = {k: v for k, v in (pins or {}).items() if k != canonicalize_name(package)}
    need = {vid: min_fix(installed, fixed) for vid, fixed, _ in advisories}
    need = {k: v for k, v in need.items() if v is not None}
    if not need:
        return None
    urgent = {vid for vid, _, rec in advisories if rec in URGENT and vid in need}
    focus = urgent or set(need)
    same_major = {vid for vid in focus if cur and need[vid].major == cur.major}
    target_set = same_major or focus  # stay in-major when that fixes something urgent
    ceiling_major = cur.major if (same_major and cur) else None

    notes: list[str] = []
    # Try to fix the whole target set; if no release is compatible, give up the advisories with
    # the highest fix floors one step at a time, so we still ship the largest safe subset.
    floors = sorted({need[v] for v in target_set}, reverse=True)
    chosen = verified = None
    for floor in floors:
        chosen, verified, blocked = _pick(package, floor, ceiling_major, py, pins, fetch, max_tries, notes)
        if chosen is not None:
            break
    if chosen is None:
        notes.append("every release that fixes an urgent advisory is incompatible with this app; "
                     "the real fix is upstream (runtime or co-pinned packages)")
        return Choice(str(floors[-1]), [], sorted(need), notes, False, blocked=True)
    fixes = sorted(vid for vid, v in need.items() if v <= chosen)
    remaining = sorted(vid for vid in need if vid not in fixes)
    if remaining:
        notes.append(f"{len(remaining)} advisories need a larger upgrade; left for a separate decision")
    return Choice(str(chosen), fixes, remaining, notes, verified)

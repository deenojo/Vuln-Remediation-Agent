"""Deterministic reachability check: is the vulnerable package actually used by the code?

This runs *before* the LLM, so the model reasons over evidence rather than guessing.
Intentionally simple (import-level, Python only). A finer, function-level check (e.g. Semgrep
rules per CVE) is a natural extension.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

# pip distribution name -> top-level import name, where they differ
IMPORT_NAMES = {
    "pyyaml": "yaml",
    "pillow": "PIL",
    "beautifulsoup4": "bs4",
    "scikit-learn": "sklearn",
    "python-dateutil": "dateutil",
    "opencv-python": "cv2",
    "pyjwt": "jwt",
    "protobuf": "google.protobuf",
}

# Packages pulled in by a framework the app imports: used even if never imported directly.
TRANSITIVE_VIA = {
    "jinja2": ["flask"],
    "werkzeug": ["flask"],
    "itsdangerous": ["flask"],
    "urllib3": ["requests"],
    "certifi": ["requests"],
}

MAX_SNIPPETS = 3


@dataclass
class Reachability:
    status: str  # "imported" | "transitive" | "not_imported" | "unknown"
    evidence: list[str] = field(default_factory=list)

    def as_text(self) -> str:
        return self.status + ("" if not self.evidence else ": " + " | ".join(self.evidence))


def import_name(package: str) -> str:
    p = package.lower()
    return IMPORT_NAMES.get(p, p.replace("-", "_"))


def _imports_in(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
    except SyntaxError:
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _usage_lines(path: Path, module: str) -> list[str]:
    top = module.split(".")[0]
    pattern = re.compile(rf"\b{re.escape(top)}\.\w+")
    out = []
    for i, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
        if pattern.search(line) and not line.lstrip().startswith(("import ", "from ")):
            out.append(f"{path.name}:{i}: {line.strip()[:160]}")
    return out


def check(package: str, ecosystem: str, code_root: str | Path | None) -> Reachability:
    if ecosystem != "PyPI" or not code_root or not Path(code_root).is_dir():
        # OS packages and non-Python code: we can't tell statically, so say so honestly.
        return Reachability("unknown", ["no static check for this ecosystem"])
    module = import_name(package)
    files = [p for p in Path(code_root).rglob("*.py") if ".venv" not in p.parts]
    imported_by: list[Path] = []
    all_imports: set[str] = set()
    for f in files:
        imps = _imports_in(f)
        all_imports |= {i.split(".")[0] for i in imps}
        if any(i == module or i.startswith(module + ".") for i in imps):
            imported_by.append(f)
    if imported_by:
        snippets = []
        for f in imported_by:
            snippets += _usage_lines(f, module)
        names = ", ".join(sorted({f.name for f in imported_by}))
        return Reachability("imported", [f"imported in {names}", *snippets[:MAX_SNIPPETS]])
    parents = [p for p in TRANSITIVE_VIA.get(package.lower(), []) if p in all_imports]
    if parents:
        return Reachability("transitive", [f"used via {', '.join(parents)}"])
    return Reachability("not_imported", [f"'{module}' is not imported by any .py file"])

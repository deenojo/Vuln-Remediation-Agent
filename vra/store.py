"""SQLite store for findings and their lifecycle.

Tracking first_seen / resolved_at per finding is what makes MTTR and burn-down possible later:
a finding that disappears from a scan is marked resolved, not deleted.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from vra.models import Finding

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    key              TEXT PRIMARY KEY,
    vuln_id          TEXT NOT NULL,
    aliases          TEXT NOT NULL,
    package          TEXT NOT NULL,
    installed_version TEXT NOT NULL,
    fixed_version    TEXT,
    ecosystem        TEXT NOT NULL,
    target           TEXT NOT NULL,
    target_type      TEXT NOT NULL,
    severity         TEXT NOT NULL,
    cvss             REAL,
    title            TEXT,
    url              TEXT,
    sources          TEXT NOT NULL,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    resolved_at      TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    scope      TEXT NOT NULL,
    found      INTEGER NOT NULL,
    new        INTEGER NOT NULL,
    resolved   INTEGER NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: str | Path = "data/findings.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def record_scan(self, findings: list[Finding], scope: list[str], now: str | None = None) -> dict:
        """Upsert this scan's findings and resolve open findings in `scope` that no longer appear.

        scope: the targets this scan covered. Only findings in these targets can be auto-resolved,
        so scanning repo A never resolves findings in repo B.
        """
        now = now or _now()
        seen = set()
        new = 0
        cur = self.conn.cursor()
        for f in findings:
            seen.add(f.dedupe_key)
            row = cur.execute(
                "SELECT resolved_at FROM findings WHERE key = ?", (f.dedupe_key,)
            ).fetchone()
            values = (
                f.vuln_id, json.dumps(f.aliases), f.package, f.installed_version, f.fixed_version,
                f.ecosystem, f.target, f.target_type, f.severity.value, f.cvss, f.title, f.url,
                json.dumps(f.sources),
            )
            if row is None:
                new += 1
                cur.execute(
                    "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)",
                    (f.dedupe_key, *values, now, now),
                )
            else:
                if row["resolved_at"] is not None:
                    new += 1  # regression: it came back
                cur.execute(
                    """UPDATE findings SET vuln_id=?, aliases=?, package=?, installed_version=?,
                       fixed_version=?, ecosystem=?, target=?, target_type=?, severity=?, cvss=?,
                       title=?, url=?, sources=?, last_seen=?, resolved_at=NULL WHERE key=?""",
                    (*values, now, f.dedupe_key),
                )
        resolved = 0
        if scope:
            placeholders = ",".join("?" * len(scope))
            open_rows = cur.execute(
                f"SELECT key FROM findings WHERE resolved_at IS NULL AND target IN ({placeholders})",
                scope,
            ).fetchall()
            for r in open_rows:
                if r["key"] not in seen:
                    cur.execute("UPDATE findings SET resolved_at=? WHERE key=?", (now, r["key"]))
                    resolved += 1
        cur.execute(
            "INSERT INTO scans (started_at, scope, found, new, resolved) VALUES (?,?,?,?,?)",
            (now, json.dumps(scope), len(findings), new, resolved),
        )
        self.conn.commit()
        return {"found": len(findings), "new": new, "resolved": resolved}

    def open_findings(self) -> list[sqlite3.Row]:
        return self.conn.execute(
            """SELECT * FROM findings WHERE resolved_at IS NULL
               ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
               WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END, cvss DESC"""
        ).fetchall()

    def mttr_hours(self) -> float | None:
        """Mean time to remediate across resolved findings, in hours."""
        row = self.conn.execute(
            """SELECT AVG((julianday(resolved_at) - julianday(first_seen)) * 24) AS h
               FROM findings WHERE resolved_at IS NOT NULL"""
        ).fetchone()
        return round(row["h"], 2) if row["h"] is not None else None

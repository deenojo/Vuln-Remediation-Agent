"""Append-only audit log: every decision and action Patchwarden takes, with its reason.

Used by the dashboard (Week 6) and as the answer to "why did this change ship?".
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    at       TEXT NOT NULL,
    actor    TEXT NOT NULL,      -- 'scanner', 'triage:<backend>', 'policy', 'remediate', 'image-heal', 'human'
    action   TEXT NOT NULL,      -- e.g. 'patched', 'verified', 'signed', 'deployed', 'rolled_back'
    subject  TEXT NOT NULL,      -- finding key, image ref, PR url...
    outcome  TEXT NOT NULL,      -- 'ok' | 'failed' | 'skipped'
    details  TEXT NOT NULL       -- JSON
);
"""


class AuditLog:
    def __init__(self, path: str | Path = "data/findings.db"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def record(self, actor: str, action: str, subject: str, outcome: str = "ok", **details) -> None:
        self.conn.execute(
            "INSERT INTO audit (at, actor, action, subject, outcome, details) VALUES (?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), actor, action, subject,
             outcome, json.dumps(details, default=str)),
        )
        self.conn.commit()

    def entries(self, limit: int = 200) -> list[sqlite3.Row]:
        return self.conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)).fetchall()

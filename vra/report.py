"""Static, self-contained HTML dashboard (no JS, no external assets) built from the findings DB.

Published to GitHub Pages by .github/workflows/dashboard.yml, so it costs $0 and anyone can
open it from the README.
"""

from __future__ import annotations

import html
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEV_COLOR = {"CRITICAL": "#b42318", "HIGH": "#dc6803", "MEDIUM": "#ca8504", "LOW": "#667085", "UNKNOWN": "#98a2b3"}


def _q(conn, sql, *args):
    try:
        return conn.execute(sql, args).fetchall()
    except sqlite3.OperationalError:
        return []  # table not created yet (e.g. no triage has run)


def app_of(target: str, target_type: str) -> str:
    """Map a finding's target to the app it belongs to.
    repo:  targets/<app>/requirements.txt -> <app>;  image: <app>:<tag> or registry/<app>:<tag> -> <app>"""
    if target_type == "image":
        name = target.rsplit("/", 1)[-1].split(":", 1)[0]
        return name.removesuffix("-patched")
    parts = target.replace("\\", "/").split("/")
    return parts[1] if len(parts) > 2 and parts[0] == "targets" else parts[0]


def collect(db: str | Path) -> dict:
    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row
    scans = [r["started_at"] for r in _q(conn, "SELECT started_at FROM scans ORDER BY started_at")]
    series = []
    for t in scans:
        row = {"t": t}
        for sev in ("CRITICAL", "HIGH"):
            row[sev] = _q(conn, """SELECT COUNT(*) c FROM findings WHERE severity=? AND first_seen<=?
                                   AND (resolved_at IS NULL OR resolved_at>?)""", sev, t, t)[0]["c"]
        row["ALL"] = _q(conn, """SELECT COUNT(*) c FROM findings WHERE first_seen<=?
                                 AND (resolved_at IS NULL OR resolved_at>?)""", t, t)[0]["c"]
        series.append(row)
    open_by_sev = {r["severity"]: r["c"] for r in _q(
        conn, "SELECT severity, COUNT(*) c FROM findings WHERE resolved_at IS NULL GROUP BY severity")}
    fixable = _q(conn, "SELECT COUNT(*) c FROM findings WHERE resolved_at IS NULL AND fixed_version IS NOT NULL")
    mttr = {r["severity"]: r["h"] for r in _q(conn, """SELECT severity,
        AVG((julianday(resolved_at)-julianday(first_seen))*24) h FROM findings
        WHERE resolved_at IS NOT NULL GROUP BY severity""")}
    resolved_total = _q(conn, "SELECT COUNT(*) c FROM findings WHERE resolved_at IS NOT NULL")
    triage = {r["recommendation"]: r["c"] for r in _q(conn, """SELECT t.recommendation, COUNT(*) c FROM triage t
        JOIN (SELECT finding_key, MAX(triaged_at) m FROM triage GROUP BY finding_key) x
        ON t.finding_key=x.finding_key AND t.triaged_at=x.m GROUP BY t.recommendation""")}
    heals = [dict(r) for r in _q(conn, """SELECT at, subject, outcome, details FROM audit
        WHERE action='patch_and_verify' ORDER BY id DESC LIMIT 5""")]
    for h in heals:
        h["details"] = json.loads(h["details"])
    # per-app view: so a newly added target reads as "new app", not as a regression
    rows = _q(conn, "SELECT target, target_type, severity, first_seen, resolved_at FROM findings")
    apps: dict[str, dict] = {}
    for r in rows:
        a = apps.setdefault(app_of(r["target"], r["target_type"]),
                            {"open": 0, "open_ch": 0, "resolved": 0, "first_seen": r["first_seen"], "rows": []})
        a["first_seen"] = min(a["first_seen"], r["first_seen"])
        a["rows"].append(r)
        if r["resolved_at"] is None:
            a["open"] += 1
            a["open_ch"] += r["severity"] in ("CRITICAL", "HIGH")
        else:
            a["resolved"] += 1
    for a in apps.values():
        pts = []
        for t in scans:
            if t < a["first_seen"]:
                continue
            pts.append(sum(1 for r in a["rows"] if r["severity"] in ("CRITICAL", "HIGH") and r["first_seen"] <= t
                           and (r["resolved_at"] is None or r["resolved_at"] > t)))
        a["trend"] = pts
        del a["rows"]
    return {
        "apps": apps,
        "series": series, "open_by_sev": open_by_sev, "fixable": fixable[0]["c"] if fixable else 0,
        "mttr": mttr, "resolved_total": resolved_total[0]["c"] if resolved_total else 0,
        "triage": triage, "heals": heals,
    }


# ------------------------------------------------------------------ svg helpers

def _line_chart(series: list[dict], w: int = 760, h: int = 260) -> str:
    if len(series) < 2:
        return ("<p class='muted'>Baseline recorded. The burn-down appears after the next scan "
                "(nightly, or run the dashboard workflow).</p>")
    pad_l, pad_r, pad_t, pad_b = 48, 120, 16, 36
    ymax = max(max(r["CRITICAL"] + r["HIGH"], 1) for r in series)
    ymax = max(ymax, 1)
    n = len(series)
    X = lambda i: pad_l + i * (w - pad_l - pad_r) / (n - 1)
    Y = lambda v: pad_t + (1 - v / ymax) * (h - pad_t - pad_b)
    parts = [f"<svg viewBox='0 0 {w} {h}' role='img' aria-label='Open Critical and High findings over time'>"]
    for k in range(5):
        v = ymax * k / 4
        parts.append(f"<line x1='{pad_l}' x2='{w - pad_r}' y1='{Y(v):.1f}' y2='{Y(v):.1f}' class='grid'/>"
                     f"<text x='{pad_l - 8}' y='{Y(v) + 4:.1f}' class='tick' text-anchor='end'>{round(v)}</text>")
    for sev in ("CRITICAL", "HIGH"):
        pts = " ".join(f"{X(i):.1f},{Y(r[sev]):.1f}" for i, r in enumerate(series))
        parts.append(f"<polyline points='{pts}' fill='none' stroke='{SEV_COLOR[sev]}' stroke-width='2.5'/>")
        last = series[-1][sev]
        parts.append(f"<text x='{X(n - 1) + 8:.1f}' y='{Y(last) + 4:.1f}' class='lbl' fill='{SEV_COLOR[sev]}'>"
                     f"{sev.title()} {last}</text>")
    for i in sorted({0, n - 1}):
        parts.append(f"<text x='{X(i):.1f}' y='{h - 12}' class='tick' text-anchor='middle'>"
                     f"{html.escape(series[i]['t'][:10])}</text>")
    parts.append("</svg>")
    return "".join(parts)


def _bars(counts: dict[str, int]) -> str:
    total = max(sum(counts.values()), 1)
    rows = []
    for sev in SEV_ORDER:
        c = counts.get(sev, 0)
        if not c:
            continue
        rows.append(f"<div class='bar'><span class='name'>{sev.title()}</span>"
                    f"<span class='track'><span class='fill' style='width:{100 * c / total:.1f}%;"
                    f"background:{SEV_COLOR[sev]}'></span></span><span class='num'>{c}</span></div>")
    return "".join(rows) or "<p class='muted'>No open findings.</p>"


def _spark(points: list[int], w: int = 140, h: int = 28) -> str:
    if len(points) < 2:
        return "<span class='muted'>new</span>"
    top = max(max(points), 1)
    step = (w - 4) / (len(points) - 1)
    pts = " ".join(f"{2 + i * step:.1f},{2 + (1 - p / top) * (h - 4):.1f}" for i, p in enumerate(points))
    color = "#067647" if points[-1] < points[0] else ("#b42318" if points[-1] > points[0] else "#667085")
    return f"<svg viewBox='0 0 {w} {h}' width='{w}' height='{h}'><polyline points='{pts}' fill='none' stroke='{color}' stroke-width='2'/></svg>"


def _apps_table(apps: dict) -> str:
    if not apps:
        return "<p class='muted'>No findings yet.</p>"
    rows = []
    for name, a in sorted(apps.items(), key=lambda kv: -kv[1]["open_ch"]):
        t = a["trend"]
        change = (f"{t[0]} → {t[-1]}" if len(t) > 1 else "first scan")
        rows.append(f"<tr><td><code>{html.escape(name)}</code></td><td class='num'>{a['open']}</td>"
                    f"<td class='num'>{a['open_ch']}</td><td class='num'>{a['resolved']}</td>"
                    f"<td>{_spark(t)}</td><td>{change}</td><td class='muted'>{html.escape(a['first_seen'][:10])}</td></tr>")
    return ("<table><tr><th>App</th><th>Open</th><th>Open Crit+High</th><th>Resolved</th><th>Crit+High trend</th>"
            "<th>Change</th><th>First scanned</th></tr>" + "".join(rows) + "</table>"
            "<p class='muted'>A new app adds findings to the totals above. Read the burn-down per app here.</p>")


# ------------------------------------------------------------------ page

CSS = """
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:#101828;margin:0;background:#f9fafb}
main{max-width:860px;margin:0 auto;padding:32px 20px}
h1{font-size:26px;margin:0}.sub{color:#475467;margin:4px 0 24px}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.kpi{background:#fff;border:1px solid #eaecf0;border-radius:10px;padding:14px}
.kpi b{display:block;font-size:26px}.kpi span{color:#475467;font-size:13px}
section{background:#fff;border:1px solid #eaecf0;border-radius:10px;padding:18px;margin-bottom:16px}
h2{font-size:17px;margin:0 0 12px}
.grid{stroke:#eaecf0}.tick{font-size:11px;fill:#667085}.lbl{font-size:12px;font-weight:600}
.bar{display:grid;grid-template-columns:90px 1fr 60px;align-items:center;gap:10px;margin:6px 0}
.track{background:#f2f4f7;border-radius:6px;height:12px;overflow:hidden;display:block}
.fill{display:block;height:100%}.num{text-align:right;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;font-size:14px}td,th{padding:6px 8px;border-bottom:1px solid #eaecf0;text-align:left}
.ok{color:#067647;font-weight:600}.bad{color:#b42318;font-weight:600}.muted{color:#667085}
footer{color:#667085;font-size:13px;margin-top:24px}
@media(max-width:640px){.kpis{grid-template-columns:repeat(2,1fr)}}
"""


def _fmt_h(h: float | None) -> str:
    if h is None:
        return "n/a"
    return f"{h:.1f} h" if h < 48 else f"{h / 24:.1f} d"


def render(data: dict, redteam: dict | None = None) -> str:
    s = data["series"]
    open_total = sum(data["open_by_sev"].values())
    crit_high = data["open_by_sev"].get("CRITICAL", 0) + data["open_by_sev"].get("HIGH", 0)
    peak = max((r["CRITICAL"] + r["HIGH"] for r in s), default=crit_high)
    reduction = f"{100 * (peak - crit_high) / peak:.0f}%" if peak else "0%"
    all_mttr = [v for v in data["mttr"].values() if v is not None]
    mttr = _fmt_h(sum(all_mttr) / len(all_mttr)) if all_mttr else None
    mttr_kpi = (f"<b>{mttr}</b><span>mean time to remediate</span>" if mttr else
                "<b>No fixes yet</b><span>MTTR starts after the first fix merges</span>")

    heal_rows = "".join(
        f"<tr><td>{html.escape(h['at'][:16].replace('T', ' '))}</td><td><code>{html.escape(h['subject'])}</code></td>"
        f"<td>{h['details'].get('fixed', 0)} CVEs fixed</td>"
        f"<td class='{'ok' if h['outcome'] == 'ok' else 'bad'}'>{'verified' if h['outcome'] == 'ok' else 'failed'}"
        f"{', signed' if h['details'].get('signed') else ''}{', deployed' if h['details'].get('deployed') else ''}"
        f"{', rolled back' if h['details'].get('rolled_back') else ''}</td></tr>"
        for h in data["heals"]
    ) or "<tr><td colspan='4' class='muted'>No image heals recorded in this database.</td></tr>"

    triage_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td class='num'>{v}</td></tr>"
        for k, v in sorted(data["triage"].items(), key=lambda kv: -kv[1])
    ) or "<tr><td colspan='2' class='muted'>No triage recorded yet.</td></tr>"

    rt = ""
    if redteam:
        rt = (f"<section><h2>Prompt-injection red team</h2><p>Against a <b>fully compromised model</b> "
              f"(obeys every attacker): model fooled <b>{redteam['fooled']}/{redteam['total']}</b>, "
              f"safety-critical attacks landed <b class='{'ok' if redteam['landed'] == 0 else 'bad'}'>"
              f"{redteam['landed']}/{redteam['critical']}</b>. The guardrails, not the model, hold the line.</p></section>")

    mttr_rows = "".join(
        f"<tr><td>{sev.title()}</td><td>{_fmt_h(data['mttr'].get(sev))}</td></tr>"
        for sev in SEV_ORDER if sev in data["mttr"]
    ) or ("<tr><td colspan='2' class='muted'>No fixes yet: MTTR starts after the first fix merges "
          "and a later scan confirms the vulnerability is gone.</td></tr>")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html><html lang='en'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>Patchwarden dashboard</title><style>{CSS}</style></head><body><main>
<h1>Patchwarden</h1><p class='sub'>Self-healing vulnerability remediation: live results from this repo's pipeline.</p>
<div class='kpis'>
<div class='kpi'><b>{open_total}</b><span>open findings</span></div>
<div class='kpi'><b>{crit_high}</b><span>open Critical + High</span></div>
<div class='kpi'><b>{reduction}</b><span>Critical + High burned down from peak</span></div>
<div class='kpi'>{mttr_kpi}</div>
</div>
<section><h2>Burn-down: open Critical and High (all apps)</h2>{_line_chart(s)}</section>
<section><h2>By app</h2>{_apps_table(data.get('apps', {}))}</section>
<section><h2>Open findings by severity</h2>{_bars(data['open_by_sev'])}
<p class='muted'>{data['fixable']} of {open_total} open findings have a fix available. {data['resolved_total']} resolved so far.</p></section>
<section><h2>Mean time to remediate by severity</h2><table>{mttr_rows}</table></section>
<section><h2>Latest triage decisions</h2><table>{triage_rows}</table></section>
<section><h2>Container self-healing</h2><table><tr><th>When</th><th>Image</th><th>Result</th><th>Status</th></tr>{heal_rows}</table></section>
{rt}
<footer>Generated {generated} by <code>patchwarden report</code>. Source: <a href='https://github.com/deenojo/Vulnerability-Remediation-Agent'>github.com/deenojo/Vulnerability-Remediation-Agent</a></footer>
</main></body></html>"""


def build(db: str | Path, out: str | Path, payloads: str | Path | None = None) -> Path:
    redteam = None
    if payloads and Path(payloads).exists():
        from vra.redteam import CRITICAL_GOALS, CompromisedBackend, run_suite

        res = run_suite(payloads, CompromisedBackend())
        crit = [r for r in res if r.goal in CRITICAL_GOALS]
        redteam = {"total": len(res), "fooled": sum(r.model_fooled for r in res),
                   "critical": len(crit), "landed": sum(r.attack_landed for r in crit)}
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(collect(db), redteam))
    return out

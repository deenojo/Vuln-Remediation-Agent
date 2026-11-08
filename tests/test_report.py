from pathlib import Path

from vra.cli import main
from vra.models import Finding, Severity
from vra.store import Store

ROOT = Path(__file__).resolve().parent.parent


def F(cve, sev):
    return Finding(vuln_id=cve, package="p" + cve, installed_version="1", fixed_version="2",
                   ecosystem="PyPI", target="r.txt", target_type="repo", severity=sev, sources=["t"])


def test_report_shows_burndown_and_kpis(tmp_path):
    db = tmp_path / "f.db"
    s = Store(db)
    a, b, c = F("CVE-1", Severity.CRITICAL), F("CVE-2", Severity.HIGH), F("CVE-3", Severity.HIGH)
    s.record_scan([a, b, c], ["r.txt"], now="2026-11-01T00:00:00+00:00")
    s.record_scan([b, c], ["r.txt"], now="2026-11-02T00:00:00+00:00")
    s.record_scan([c], ["r.txt"], now="2026-11-03T00:00:00+00:00")
    out = tmp_path / "site" / "index.html"
    assert main(["--db", str(db), "report", "--out", str(out),
                 "--payloads", str(ROOT / "eval/redteam/payloads.yaml")]) == 0
    page = out.read_text()
    assert "<polyline" in page                      # burn-down drawn
    assert ">67%<" in page                          # 3 crit+high at peak -> 1 open
    assert "safety-critical attacks landed" in page
    assert "<script" not in page                    # static, no JS


def test_report_handles_empty_db(tmp_path):
    out = tmp_path / "i.html"
    assert main(["--db", str(tmp_path / "e.db"), "report", "--out", str(out), "--payloads", "nope"]) == 0
    page = out.read_text()
    assert "Baseline recorded" in page and "No fixes yet" in page and "n/a" not in page


def test_app_attribution_and_per_app_table(tmp_path):
    from vra.report import app_of

    assert app_of("targets/demo-vulnerable-app-2/requirements.txt", "repo") == "demo-vulnerable-app-2"
    assert app_of("demo-vulnerable-app:latest", "image") == "demo-vulnerable-app"
    assert app_of("localhost:5000/patchwarden-demo:4-patched", "image") == "patchwarden-demo"
    db = tmp_path / "f.db"
    s = Store(db)
    a = Finding(vuln_id="CVE-1", package="x", installed_version="1", fixed_version="2", ecosystem="PyPI",
                target="targets/app-a/requirements.txt", target_type="repo", severity=Severity.HIGH, sources=["t"])
    b = a.model_copy(update={"target": "targets/app-b/requirements.txt"})
    s.record_scan([a], [a.target], now="2026-11-01T00:00:00+00:00")
    s.record_scan([], [a.target], now="2026-11-02T00:00:00+00:00")          # app-a fixed
    s.record_scan([b], [b.target], now="2026-11-03T00:00:00+00:00")          # app-b added
    out = tmp_path / "i.html"
    main(["--db", str(db), "report", "--out", str(out), "--payloads", "nope"])
    page = out.read_text()
    assert "<code>app-a</code>" in page and "<code>app-b</code>" in page and "1 → 0" in page and "first scan" in page

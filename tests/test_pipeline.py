import json
from pathlib import Path

from vra.cli import main
from vra.models import Finding, Severity, canonical_id
from vra.normalize import merge_findings, normalize_target, summarize
from vra.parsers import parse_osv, parse_trivy
from vra.store import Store

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


def test_canonical_id_prefers_cve():
    assert canonical_id("GHSA-x84v-xcm2-53pg", ["CVE-2018-18074"]) == "CVE-2018-18074"
    assert canonical_id("GHSA-only", []) == "GHSA-only"


def test_severity_parsing():
    assert Severity.parse("moderate") is Severity.MEDIUM
    assert Severity.parse(None) is Severity.UNKNOWN
    assert Severity.from_cvss(9.8) is Severity.CRITICAL
    assert Severity.from_cvss(7.5) is Severity.HIGH


def test_parse_trivy_fs():
    findings = parse_trivy(load("trivy-fs.json"), target_type="repo")
    assert len(findings) == 4
    pyyaml = next(f for f in findings if f.package == "pyyaml")
    assert pyyaml.severity is Severity.CRITICAL
    assert pyyaml.fixed_version == "5.4"
    assert pyyaml.cvss == 9.8


def test_parse_trivy_image_uses_image_as_target_and_handles_no_fix():
    findings = parse_trivy(load("trivy-image.json"), target_type="image")
    assert {f.target for f in findings} == {"demo-vulnerable-app:latest"}
    unfixed = next(f for f in findings if f.package == "libexample")
    assert unfixed.fixed_version is None and not unfixed.fixable


def test_parse_osv_maps_ghsa_to_cve_and_fix():
    findings = parse_osv(load("osv.json"))
    req = next(f for f in findings if f.package == "requests")
    assert req.vuln_id == "CVE-2018-18074"
    assert "GHSA-x84v-xcm2-53pg" in req.aliases
    assert req.fixed_version == "2.20.0"


def test_merge_dedupes_across_scanners():
    raw = parse_trivy(load("trivy-fs.json"), "repo") + parse_osv(load("osv.json"))
    merged = merge_findings(raw)
    assert len(raw) == 6
    assert len(merged) == 5  # requests CVE-2018-18074 reported by both
    req = next(f for f in merged if f.package == "requests")
    assert req.sources == ["osv-scanner", "trivy"]
    assert merged[0].severity is Severity.CRITICAL  # sorted worst-first


def test_normalize_target_handles_absolute_and_windows_paths():
    assert normalize_target("/work/repo/app/requirements.txt", "/work/repo") == "app/requirements.txt"
    assert normalize_target("C:\\work\\repo\\req.txt", "C:\\work\\repo") == "req.txt"
    assert normalize_target("./req.txt") == "req.txt"


def test_summarize():
    merged = merge_findings(parse_trivy(load("trivy-image.json"), "image"))
    s = summarize(merged)
    assert s["TOTAL"] == 2 and s["HIGH"] == 1 and s["LOW"] == 1 and s["FIXABLE"] == 1


def _finding(**kw):
    base = dict(
        vuln_id="CVE-1", package="p", installed_version="1", ecosystem="PyPI",
        target="t/req.txt", target_type="repo", severity=Severity.HIGH, sources=["trivy"],
    )
    base.update(kw)
    return Finding(**base)


def test_store_tracks_lifecycle_and_mttr(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    a, b = _finding(vuln_id="CVE-1"), _finding(vuln_id="CVE-2")
    r1 = store.record_scan([a, b], ["t/req.txt"], now="2026-11-01T00:00:00+00:00")
    assert r1 == {"found": 2, "new": 2, "resolved": 0}
    # CVE-2 fixed 12 hours later
    r2 = store.record_scan([a], ["t/req.txt"], now="2026-11-01T12:00:00+00:00")
    assert r2 == {"found": 1, "new": 0, "resolved": 1}
    assert len(store.open_findings()) == 1
    assert store.mttr_hours() == 12.0


def test_store_does_not_resolve_out_of_scope_targets(tmp_path):
    store = Store(tmp_path / "db.sqlite")
    store.record_scan([_finding(target="repoA/req.txt")], ["repoA/req.txt"])
    store.record_scan([], ["repoB/req.txt"])  # scanning B must not resolve A
    assert len(store.open_findings()) == 1


def test_cli_end_to_end(tmp_path, capsys):
    db = str(tmp_path / "f.db")
    rc = main([
        "--db", db, "ingest",
        "--trivy-fs", str(FIX / "trivy-fs.json"),
        "--osv", str(FIX / "osv.json"),
        "--trivy-image", str(FIX / "trivy-image.json"),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "8 raw findings -> 7 unique (1 duplicates merged)" in out
    main(["--db", db, "summary"])
    summary = json.loads(capsys.readouterr().out)
    assert summary["open"]["TOTAL"] == 7
    assert summary["open"]["CRITICAL"] == 2

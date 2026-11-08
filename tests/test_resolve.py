from packaging.version import Version

from vra.resolve import choose, fix_candidates, manifest_pins, min_fix, runtime_python

PY39 = "3.9"


def fake_pypi(releases, meta):
    """releases: list of versions; meta: {version: (requires_python, [requires_dist])}"""
    def fetch(pkg, version):
        if version is None:
            return {"releases": {v: [{"f": 1}] for v in releases}}
        rp, rd = meta.get(version, (None, []))
        return {"info": {"requires_python": rp, "requires_dist": rd}}
    return fetch


def test_min_fix_prefers_backport_in_same_line():
    assert fix_candidates("3.0.0, 2.11.3") == [Version("2.11.3"), Version("3.0.0")]
    assert min_fix("2.10", "3.0.0, 2.11.3") == Version("2.11.3")
    assert min_fix("2.12", "2.11.3, 3.0.0") == Version("3.0.0")
    assert min_fix("9.0", "2.0") is None


def test_stays_in_major_and_reports_remaining():
    adv = [("CVE-A", "0.12.3", "fix_now"), ("CVE-B", "1.0", "fix_soon"), ("CVE-C", "2.2.5", "monitor")]
    c = choose("flask", "0.12.2", adv)
    assert c.version == "0.12.3"
    assert c.fixes == ["CVE-A"] and c.remaining == ["CVE-B", "CVE-C"]


def test_goes_major_only_when_nothing_urgent_is_fixable_in_major():
    c = choose("jinja2", "2.10", [("CVE-X", "3.1.4", "fix_now")])
    assert c.version == "3.1.4"


def test_skips_release_that_drops_runtime_python():
    fetch = fake_pypi(["2.31.0", "2.32.0", "2.33.0"],
                      {"2.33.0": (">=3.10", []), "2.32.0": (">=3.8", []), "2.31.0": (">=3.7", [])})
    adv = [("CVE-1", "2.32.0", "fix_now")]
    c = choose("requests", "2.19.1", adv, py=PY39, fetch=fetch)
    assert c.version == "2.32.0" and c.verified


def test_skips_release_that_conflicts_with_a_pin():
    fetch = fake_pypi(["1.0", "1.1"], {"1.0": (None, ["itsdangerous>=2.2"]), "1.1": (None, ["itsdangerous>=0.24"])})
    c = choose("flask", "0.12.2", [("CVE-1", "1.0", "fix_now")], py=PY39,
               pins={"itsdangerous": Version("1.1.0")}, fetch=fetch)
    assert c.version == "1.1" and any("pins 1.1.0" in n for n in c.notes)


def test_marker_scoped_requirements_are_ignored_when_not_applicable():
    fetch = fake_pypi(["5.0"], {"5.0": (None, ['importlib-metadata>=9; python_version < "3.8"'])})
    c = choose("x", "4.0", [("CVE-1", "5.0", "fix_now")], py=PY39,
               pins={"importlib-metadata": Version("1.0")}, fetch=fetch)
    assert c.verified


def test_unverified_without_metadata():
    c = choose("x", "1.0", [("CVE-1", "1.1", "fix_now")], fetch=lambda p, v: None)
    assert c.version == "1.1" and not c.verified


def test_reads_runtime_and_pins(tmp_path):
    d = tmp_path / "app"
    d.mkdir()
    (d / "Dockerfile").write_text("FROM python:3.9.18-slim-bookworm\n")
    (d / "requirements.txt").write_text("# c\nFlask==0.12.2\nitsdangerous==1.1.0  # x\n")
    assert runtime_python("app/requirements.txt", tmp_path) == "3.9"
    assert manifest_pins("app/requirements.txt", tmp_path) == {"flask": Version("0.12.2"), "itsdangerous": Version("1.1.0")}


def test_falls_back_to_largest_compatible_subset():
    fetch = fake_pypi(["2.20.0", "2.31.0", "2.32.4", "2.33.0"],
                      {"2.33.0": (">=3.10", []), "2.32.4": (">=3.8", []), "2.31.0": (">=3.7", []), "2.20.0": (None, [])})
    adv = [("CVE-old", "2.20.0", "fix_now"), ("CVE-mid", "2.32.4", "fix_soon"), ("CVE-new", "2.33.0", "fix_now")]
    c = choose("requests", "2.19.1", adv, py=PY39, fetch=fetch)
    assert c.version == "2.32.4" and c.fixes == ["CVE-mid", "CVE-old"] and c.remaining == ["CVE-new"]


def test_blocked_when_nothing_compatible():
    fetch = fake_pypi(["3.0"], {"3.0": (None, ["markupsafe>=2.1"])})
    c = choose("werkzeug", "0.16.1", [("CVE-1", "3.0", "fix_now")], py=PY39,
               pins={"markupsafe": Version("1.1.1")}, fetch=fetch)
    assert c.blocked and c.fixes == [] and c.remaining == ["CVE-1"]

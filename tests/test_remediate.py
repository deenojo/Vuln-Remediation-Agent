import shutil
import subprocess
from pathlib import Path

import pytest

from vra.cli import main
from vra.policy import Decision, classify_bump, evaluate, load_policy
from vra.remediate import FixPlan, ForbiddenPathError, apply_plan, check_path
from vra.policy import GateResult

ROOT = Path(__file__).resolve().parent.parent
FIX = Path(__file__).parent / "fixtures"
POLICY = load_policy(ROOT / "policy" / "policy.yaml")


def gate(**kw):
    base = dict(package="pyyaml", installed="5.3.1", fixed="5.3.2", ecosystem="PyPI",
                recommendation="fix_now", risk_score=90, confidence=0.8, policy=POLICY)
    base.update(kw)
    return evaluate(**base)


def test_classify_bump():
    assert classify_bump("5.3.1", "5.3.2", "PyPI") == "patch"
    assert classify_bump("5.3.1", "5.4", "PyPI") == "minor"
    assert classify_bump("0.12.2", "1.0", "PyPI") == "major"
    assert classify_bump("1.1.1n-0+deb11u3", "1.1.1n-0+deb11u4", "debian") == "os_patch"
    assert classify_bump("weird", "1.0", "PyPI") == "major"


def test_patch_bump_with_high_risk_auto_merges():
    assert gate().decision is Decision.AUTO_MERGE


def test_minor_and_major_need_review():
    assert gate(fixed="5.4").decision is Decision.HUMAN_REVIEW
    assert gate(fixed="6.0").decision is Decision.HUMAN_REVIEW


def test_always_review_package_and_low_confidence_and_monitor():
    assert gate(package="flask").decision is Decision.HUMAN_REVIEW
    assert gate(confidence=0.3).decision is Decision.HUMAN_REVIEW
    assert gate(recommendation="monitor").decision is Decision.HUMAN_REVIEW
    assert gate(risk_score=10).decision is Decision.HUMAN_REVIEW


def test_no_fix_skips():
    assert gate(fixed=None).decision is Decision.SKIP


def test_kill_switch(monkeypatch):
    monkeypatch.setenv("VRA_AUTOMERGE_DISABLED", "1")
    r = gate()
    assert r.decision is Decision.HUMAN_REVIEW and any("kill switch" in x for x in r.reasons)
    assert gate(policy={**POLICY, "auto_merge_enabled": False}).decision is Decision.HUMAN_REVIEW


@pytest.mark.parametrize("bad", [
    "policy/policy.yaml", ".github/workflows/scan.yml", "../etc/requirements.txt",
    "/abs/requirements.txt", "app.py", "setup.py",
])
def test_remediation_refuses_non_manifest_paths(bad):
    with pytest.raises(ForbiddenPathError):
        check_path(bad)


def test_allowed_manifests():
    check_path("targets/demo-vulnerable-app/requirements.txt")
    check_path("requirements-dev.txt")


def _plan(manifest, pkg="PyYAML", ver="5.4"):
    return FixPlan(manifest=manifest, package=pkg, installed="5.3.1", target_version=ver,
                   vuln_ids=["CVE-1"], risk_score=90, recommendation="fix_now", confidence=0.8,
                   rationale="r", gate=GateResult(Decision.HUMAN_REVIEW, "minor"))


def test_apply_plan_rewrites_only_the_pin_and_keeps_comments(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("# comment\nflask==0.12.2\npyyaml==5.3.1  # pinned\npyyaml-extra==1.0\n")
    assert apply_plan(_plan("requirements.txt"), tmp_path)
    assert req.read_text() == "# comment\nflask==0.12.2\npyyaml==5.4  # pinned\npyyaml-extra==1.0\n"


def test_cli_end_to_end_plan_and_commit(tmp_path, capsys):
    # Work in a throwaway git copy of the demo target.
    repo = tmp_path / "repo"
    # frozen copy of the original vulnerable app, so tests don't depend on the live demo pins
    shutil.copytree(FIX / "demo-app", repo / "targets" / "demo-vulnerable-app")
    shutil.copytree(ROOT / "policy", repo / "policy")
    run = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)
    run("init", "-q", "-b", "main")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init", "--allow-empty")
    run("add", "-A")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "seed")
    db = str(tmp_path / "f.db")
    main(["--db", db, "ingest", "--trivy-fs", str(FIX / "trivy-fs.json"), "--osv", str(FIX / "osv.json")])
    main(["--db", db, "triage", "--code-root", str(repo / "targets" / "demo-vulnerable-app")])
    capsys.readouterr()

    main(["--db", db, "remediate", "--offline", "--repo-root", str(repo), "--policy", str(repo / "policy" / "policy.yaml")])
    out = capsys.readouterr().out
    assert "[human_review] fix(deps): bump flask" in out          # always-review package
    assert "[auto_merge  ] fix(deps): bump jinja2 2.10 -> 2.10.1" in out  # patch bump
    assert "bump pillow" in out                                    # still fixed, but reviewed

    subprocess.run(["git", "config", "user.email", "t@t"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    main(["--db", db, "remediate", "--mode", "commit", "--offline", "--repo-root", str(repo),
          "--policy", str(repo / "policy" / "policy.yaml")])
    branches = subprocess.run(["git", "branch"], cwd=repo, capture_output=True, text=True).stdout
    assert "vra/fix-jinja2-2.10.1" in branches
    diff = subprocess.run(["git", "diff", "main", "vra/fix-jinja2-2.10.1"], cwd=repo,
                          capture_output=True, text=True).stdout
    assert "+jinja2==2.10.1" in diff and "policy" not in diff

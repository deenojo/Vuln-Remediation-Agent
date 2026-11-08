import json
import subprocess
from pathlib import Path

from vra.heal import heal_image, verify

FIX = Path(__file__).parent / "fixtures"


def report(vulns, name="demo:1"):
    return {"ArtifactName": name, "Results": [{"Target": f"{name} (debian 11)", "Type": "debian",
                                               "Vulnerabilities": vulns}]}


def v(cve, pkg="openssl", sev="HIGH", fixed="2.0"):
    return {"VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": "1.0",
            "FixedVersion": fixed, "Severity": sev}


BEFORE = report([v("CVE-1"), v("CVE-2", "zlib", "CRITICAL")])


# ---- verify (pure)

def test_verify_passes_when_all_targeted_fixed():
    r = verify(BEFORE, report([]))
    assert r.passed and r.fixed == ["CVE-1 (openssl)", "CVE-2 (zlib)"]


def test_verify_fails_when_cve_remains():
    r = verify(BEFORE, report([v("CVE-2", "zlib", "CRITICAL")]))
    assert not r.passed and r.still_present == ["CVE-2 (zlib)"]


def test_verify_fails_when_patch_introduces_high():
    r = verify(BEFORE, report([v("CVE-9", "libnew", "HIGH")]))
    assert not r.passed and "CVE-9 (libnew) HIGH" in r.introduced


def test_verify_ignores_new_low_findings():
    assert verify(BEFORE, report([v("CVE-9", "libnew", "LOW")])).passed


def test_verify_nothing_to_patch():
    r = verify(report([v("CVE-1", fixed="")]), report([]))
    assert not r.passed and "nothing fixable" in r.reasons[0]


# ---- orchestration with a fake runner

class FakeRunner:
    """Writes canned trivy reports and records every command."""

    def __init__(self, before, after, fail=()):
        self.before, self.after, self.fail, self.calls = before, after, set(fail), []

    def __call__(self, cmd):
        self.calls.append(cmd)
        tool = cmd[0] if cmd[0] != "kubectl" else f"kubectl {cmd[1]}"
        if cmd[0] == "trivy":
            out = Path(cmd[cmd.index("--output") + 1])
            data = self.after if cmd[-1].endswith("-patched") else self.before
            out.write_text(json.dumps(data))
        rc = 1 if tool in self.fail else 0
        return subprocess.CompletedProcess(cmd, rc, "", "boom" if rc else "")


def tools(runner):
    return [c[0] if c[0] != "kubectl" else f"kubectl {c[1]}" for c in runner.calls]


def test_happy_path_patch_verify_sign_deploy(tmp_path):
    r = FakeRunner(BEFORE, report([]))
    res = heal_image("ghcr.io/me/demo:1", workdir=tmp_path, push=True, sign=True,
                     deployment="demo", runner=r, buildkit_addr="docker-container://buildkitd")
    assert res.ok and res.signed and res.deployed and not res.rolled_back
    assert res.patched_image == "ghcr.io/me/demo:1-patched"
    assert tools(r) == ["trivy", "copa", "trivy", "docker", "cosign", "kubectl set", "kubectl rollout"]
    copa = r.calls[1]
    assert copa[copa.index("-t") + 1] == "1-patched" and "--addr" in copa


def test_failed_verification_never_signs_or_deploys(tmp_path):
    r = FakeRunner(BEFORE, report([v("CVE-1")]))
    res = heal_image("demo:1", workdir=tmp_path, sign=True, deployment="demo", runner=r)
    assert not res.ok and not res.signed and not res.deployed
    assert "cosign" not in tools(r) and "kubectl set" not in tools(r)


def test_failed_rollout_rolls_back(tmp_path):
    r = FakeRunner(BEFORE, report([]), fail={"kubectl rollout"})
    # make 'rollout undo' succeed: only the first rollout call (status) fails
    calls = []

    def runner(cmd):
        res = r(cmd)
        if cmd[:3] == ["kubectl", "rollout", "undo"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        calls.append(cmd)
        return res

    res = heal_image("demo:1", workdir=tmp_path, deployment="demo", runner=runner)
    assert res.rolled_back and not res.deployed
    assert ["kubectl", "rollout", "undo", "deployment/demo"] in r.calls


def test_copa_failure_stops_pipeline(tmp_path):
    r = FakeRunner(BEFORE, report([]), fail={"copa"})
    res = heal_image("demo:1", workdir=tmp_path, runner=r)
    assert not res.ok and res.patched_image is None and tools(r) == ["trivy", "copa"]


def test_nothing_fixable_skips_copa(tmp_path):
    r = FakeRunner(report([v("CVE-1", fixed="")]), report([]))
    res = heal_image("demo:1", workdir=tmp_path, runner=r)
    assert tools(r) == ["trivy"] and "skipped" in res.steps[-1]


def test_unsigned_image_is_not_deployed(tmp_path):
    r = FakeRunner(BEFORE, report([]), fail={"cosign"})
    res = heal_image("demo:1", workdir=tmp_path, sign=True, deployment="demo", runner=r)
    assert res.ok and not res.signed and not res.deployed

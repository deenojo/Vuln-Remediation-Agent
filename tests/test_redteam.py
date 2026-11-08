from pathlib import Path

from vra.cli import main
from vra.redteam import CRITICAL_GOALS, CompromisedBackend, run_suite

PAYLOADS = Path(__file__).resolve().parent.parent / "eval" / "redteam" / "payloads.yaml"


def test_guardrails_hold_against_a_fully_compromised_model():
    results = run_suite(PAYLOADS, CompromisedBackend())
    assert len(results) >= 9
    # The model obeyed the attacker every time it could produce valid output...
    assert all(r.model_fooled for r in results)
    # ...yet no safety-critical goal survived the guardrails, and neither did nuisance escalation.
    assert [r.id for r in results if r.attack_landed] == []


def test_every_critical_goal_is_covered():
    goals = {r.goal for r in run_suite(PAYLOADS, CompromisedBackend())}
    assert CRITICAL_GOALS <= goals


def test_cli_redteam_exit_code(capsys):
    assert main(["redteam", "--payloads", str(PAYLOADS)]) == 0
    out = capsys.readouterr().out
    assert "Safety-critical attacks landed: 0/" in out

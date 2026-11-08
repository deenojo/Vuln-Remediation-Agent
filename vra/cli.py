"""Command-line entry point.

  vra ingest --trivy-fs reports/trivy-fs.json --osv reports/osv.json --trivy-image reports/trivy-img.json
  vra list [--severity HIGH]
  vra summary
  vra triage --backend heuristic|anthropic|ollama --code-root targets/demo-vulnerable-app
  vra eval --labels eval/labels.csv
  vra remediate --mode plan|commit|pr
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vra.models import Severity
from vra.normalize import merge_findings, summarize
from vra.parsers import parse_osv, parse_trivy
from vra.store import Store


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def cmd_ingest(args: argparse.Namespace) -> int:
    raw = []
    for p in args.trivy_fs or []:
        raw += parse_trivy(_load(p), target_type="repo")
    for p in args.trivy_image or []:
        raw += parse_trivy(_load(p), target_type="image")
    for p in args.osv or []:
        raw += parse_osv(_load(p))
    findings = merge_findings(raw, root=args.root)
    scope = sorted({f.target for f in findings} | set(args.scope or []))
    result = Store(args.db).record_scan(findings, scope)
    print(
        f"Ingested {len(raw)} raw findings -> {len(findings)} unique "
        f"({len(raw) - len(findings)} duplicates merged). "
        f"New: {result['new']}, resolved: {result['resolved']}"
    )
    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps([f.model_dump(mode="json") for f in findings], indent=2)
        )
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    floor = Severity.parse(args.severity).rank if args.severity else 0
    rows = [r for r in Store(args.db).open_findings() if Severity.parse(r["severity"]).rank >= floor]
    for r in rows:
        fix = r["fixed_version"] or "no fix"
        print(
            f"{r['severity']:<8} {r['vuln_id']:<20} {r['package']} {r['installed_version']} "
            f"-> {fix}  [{r['target']}]"
        )
    print(f"\n{len(rows)} open findings")
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    store = Store(args.db)
    rows = store.open_findings()
    counts = {s.value: 0 for s in Severity}
    for r in rows:
        counts[r["severity"]] += 1
    counts["TOTAL"] = len(rows)
    counts["FIXABLE"] = sum(1 for r in rows if r["fixed_version"])
    print(json.dumps({"open": counts, "mttr_hours": store.mttr_hours()}, indent=2))
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    from vra.llm import get_backend
    from vra.triage import triage_one

    store = Store(args.db)
    backend = get_backend(args.backend)
    findings = store.open_finding_models()
    # Cost cap (OWASP LLM10, unbounded consumption): worst findings get the model, the rest the heuristic.
    findings.sort(key=lambda f: (-f.severity.rank, -(f.cvss or 0)))
    results = [
        triage_one(f, args.code_root, backend if i < args.max_llm_calls else None)
        for i, f in enumerate(findings)
    ]
    store.record_triage(results)
    by_key = {f.dedupe_key: f for f in findings}
    for r in sorted(results, key=lambda x: -x.risk_score):
        f = by_key[r.finding_key]
        print(f"{r.risk_score:>3}  {r.recommendation.value:<17} {f.vuln_id:<18} {f.package:<10} "
              f"reach={r.reachability.split(':')[0]}")
        if args.verbose:
            print(f"     {r.rationale}")
    urgent = sum(1 for r in results if r.recommendation.value == "fix_now")
    print(f"\n{len(results)} findings triaged by {backend.name if backend else 'heuristic'}; "
          f"{urgent} need action now")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    """Compare the latest triage against hand labels (CSV: vuln_id,package,expected)."""
    import csv

    store = Store(args.db)
    triage = store.latest_triage()
    findings = {(f.vuln_id, f.package.lower()): f for f in store.open_finding_models()}
    total = agree = 0
    misses = []
    with open(args.labels, newline="") as fh:
        for row in csv.DictReader(fh):
            f = findings.get((row["vuln_id"], row["package"].lower()))
            if not f or f.dedupe_key not in triage:
                continue
            total += 1
            got = triage[f.dedupe_key]["recommendation"]
            if got == row["expected"]:
                agree += 1
            else:
                misses.append(f"{row['vuln_id']} {row['package']}: expected {row['expected']}, got {got}")
    if not total:
        print("No labeled findings matched the latest triage.")
        return 1
    print(f"Agreement with hand labels: {agree}/{total} ({100 * agree / total:.0f}%)")
    for m in misses:
        print("  miss:", m)
    return 0


def cmd_remediate(args: argparse.Namespace) -> int:
    from vra.policy import load_policy
    from vra.remediate import (
        build_plans, commit_on_branch, github_context, open_pr, pr_body, pr_title,
    )

    store = Store(args.db)
    from vra.resolve import pypi_fetcher

    plans = build_plans(
        store.open_finding_models(), store.latest_triage(), load_policy(args.policy),
        repo_root=args.repo_root, fetch=None if args.offline else pypi_fetcher,
    )
    for manifest, pkg, choice in getattr(build_plans, "blocked", []):
        print(f"[blocked     ] {pkg} in {manifest}: no compatible fix ({len(choice.remaining)} advisories)")
        for n in choice.notes[-3:]:
            print(f"      - {n}")
    if not plans:
        print("Nothing to remediate (no fixable, triaged dependency findings).")
        return 0
    repo, token = github_context()
    for plan in plans:
        print(f"[{plan.gate.decision.value:<12}] {pr_title(plan)}")
        for r in plan.gate.reasons + plan.notes:
            print(f"      - {r}")
        if plan.remaining:
            print(f"      - left for a larger upgrade: {len(plan.remaining)} advisories")
        if args.show_body:
            print(pr_body(plan))
        if args.mode == "plan":
            continue
        changed = commit_on_branch(plan, args.repo_root, args.base)
        print(f"      branch {plan.branch}: {'committed' if changed else 'no change (pin not found)'}")
        if args.mode == "pr" and changed:
            if not (repo and token):
                print("      skipped PR: set GITHUB_REPOSITORY and GITHUB_TOKEN")
                continue
            subprocess_push(plan.branch, args.repo_root)
            pr = open_pr(plan, repo, token, args.base)
            print(f"      opened {pr.get('html_url')} [{plan.label}]")
    return 0


def cmd_heal(args: argparse.Namespace) -> int:
    import os

    from vra.audit import AuditLog
    from vra.heal import heal_image
    from vra.policy import load_policy

    policy = load_policy(args.policy)
    rule = (policy.get("auto_merge") or {}).get("os_patch", {})
    automation_on = (
        policy.get("auto_merge_enabled", False)
        and rule.get("allowed", False)
        and os.environ.get("VRA_AUTOMERGE_DISABLED") != "1"
    )
    audit = AuditLog(args.db)
    if not automation_on:
        print("Policy blocks automatic OS patching (kill switch or os_patch not allowed). Nothing done.")
        audit.record("policy", "heal_blocked", args.image, "skipped")
        return 0
    res = heal_image(
        args.image, workdir=args.workdir, patched_tag=args.patched_tag,
        buildkit_addr=args.buildkit_addr, push=args.push, sign=args.sign,
        deployment=args.deployment, container=args.container, kind_cluster=args.kind_cluster,
    )
    for step in res.steps:
        print(" -", step)
    v = res.verification
    if v:
        print(f"Verification: {'PASSED' if v.passed else 'FAILED'} | before {v.before_count} -> after "
              f"{v.after_count} fixable OS findings | " + "; ".join(v.reasons))
    audit.record("image-heal", "patch_and_verify", args.image, "ok" if res.ok else "failed",
                 patched=res.patched_image, fixed=len(v.fixed) if v else 0,
                 still_present=v.still_present if v else [], introduced=v.introduced if v else [],
                 signed=res.signed, deployed=res.deployed, rolled_back=res.rolled_back, steps=res.steps)
    nothing_to_do = any("nothing fixable" in st for st in res.steps)
    return 0 if (res.ok or nothing_to_do) else 1


def cmd_redteam(args: argparse.Namespace) -> int:
    from vra.llm import get_backend
    from vra.redteam import CRITICAL_GOALS, CompromisedBackend, report, run_suite

    backend = CompromisedBackend() if args.backend == "compromised" else get_backend(args.backend)
    if backend is None:
        print("The heuristic backend has no model to attack; use compromised, anthropic or ollama.")
        return 1
    results = run_suite(args.payloads, backend)
    print(f"Red-team suite against backend: {backend.name}\n")
    print(report(results))
    landed = [r for r in results if r.attack_landed and r.goal in CRITICAL_GOALS]
    return 1 if landed else 0


def cmd_report(args: argparse.Namespace) -> int:
    from vra.report import build

    path = build(args.db, args.out, args.payloads)
    print(f"Dashboard written to {path}")
    return 0


def subprocess_push(branch: str, repo_root: str) -> None:
    import subprocess

    subprocess.run(["git", "push", "-f", "origin", branch], cwd=repo_root, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="patchwarden", description="Patchwarden: self-healing vulnerability remediation agent.\n" + __doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db", default="data/findings.db")
    sub = parser.add_subparsers(dest="cmd", required=True)

    ing = sub.add_parser("ingest", help="Normalize scanner reports and record a scan")
    ing.add_argument("--trivy-fs", action="append")
    ing.add_argument("--trivy-image", action="append")
    ing.add_argument("--osv", action="append")
    ing.add_argument("--scope", action="append", help="Extra targets covered by this scan")
    ing.add_argument("--json-out", help="Write merged findings as JSON")
    ing.add_argument(
        "--root", default=str(Path.cwd()), help="Repo root; absolute scanner paths are made relative to it"
    )
    ing.set_defaults(func=cmd_ingest)

    ls = sub.add_parser("list", help="List open findings")
    ls.add_argument("--severity", help="Minimum severity, e.g. HIGH")
    ls.set_defaults(func=cmd_list)

    sm = sub.add_parser("summary", help="Open counts by severity + MTTR")
    sm.set_defaults(func=cmd_summary)

    tr = sub.add_parser("triage", help="Score and explain open findings")
    tr.add_argument("--backend", default="heuristic", choices=["heuristic", "anthropic", "ollama"])
    tr.add_argument("--code-root", help="Source tree used for reachability checks")
    tr.add_argument("-v", "--verbose", action="store_true")
    tr.add_argument("--max-llm-calls", type=int, default=50, help="Cost cap; the rest use the heuristic")
    tr.set_defaults(func=cmd_triage)

    ev = sub.add_parser("eval", help="Measure triage agreement with hand labels")
    ev.add_argument("--labels", required=True)
    ev.set_defaults(func=cmd_eval)

    rm = sub.add_parser("remediate", help="Plan / commit / open PRs for fixes, gated by policy")
    rm.add_argument("--mode", choices=["plan", "commit", "pr"], default="plan",
                    help="plan: print only; commit: local branches; pr: push + open PRs")
    rm.add_argument("--policy", default="policy/policy.yaml")
    rm.add_argument("--repo-root", default=".")
    rm.add_argument("--base", default="main")
    rm.add_argument("--show-body", action="store_true")
    rm.add_argument("--offline", action="store_true", help="Skip PyPI compatibility checks")
    rm.set_defaults(func=cmd_remediate)

    hl = sub.add_parser("heal", help="Patch OS CVEs in an image (Copa), verify, sign, deploy")
    hl.add_argument("image")
    hl.add_argument("--policy", default="policy/policy.yaml")
    hl.add_argument("--workdir", default="reports")
    hl.add_argument("--patched-tag")
    hl.add_argument("--buildkit-addr", help="e.g. docker-container://buildkitd")
    hl.add_argument("--push", action="store_true", help="docker push the patched image")
    hl.add_argument("--sign", action="store_true", help="cosign sign the patched image")
    hl.add_argument("--deployment", help="Kubernetes deployment to roll out to")
    hl.add_argument("--container", default="app")
    hl.add_argument("--kind-cluster", help="Load the patched image into this kind cluster before rollout")
    hl.set_defaults(func=cmd_heal)

    rt = sub.add_parser("redteam", help="Run the prompt-injection suite against a triage backend")
    rt.add_argument("--backend", default="compromised", choices=["compromised", "anthropic", "ollama", "heuristic"])
    rt.add_argument("--payloads", default="eval/redteam/payloads.yaml")
    rt.set_defaults(func=cmd_redteam)

    rp = sub.add_parser("report", help="Build the static HTML dashboard")
    rp.add_argument("--out", default="site/index.html")
    rp.add_argument("--payloads", default="eval/redteam/payloads.yaml")
    rp.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

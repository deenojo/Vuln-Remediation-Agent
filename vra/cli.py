"""Command-line entry point.

  vra ingest --trivy-fs reports/trivy-fs.json --osv reports/osv.json --trivy-image reports/trivy-img.json
  vra list [--severity HIGH]
  vra summary
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vra", description=__doc__)
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

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

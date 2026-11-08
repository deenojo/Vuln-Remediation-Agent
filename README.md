# Self-Healing Vulnerability Remediation Agent

An AI agent that finds dependency and container vulnerabilities, triages them by real risk, fixes them automatically where policy allows, and proves each fix by re-scanning.

> **Status: Week 1 of 6, scanning and findings database.** See the [roadmap](#roadmap).

## Architecture

```
 trigger (nightly / PR / new CVE)
        │
        ▼
 ┌────────────┐   ┌───────────────┐   ┌─────────────┐  low risk  ┌───────────┐
 │    Scan    │──▶│ Triage agent  │──▶│ Policy gate │──────────▶│ Auto-fix  │
 │ Trivy, OSV │   │ reachability  │   │ (plain code)│            │ PR / Copa │
 │ Syft SBOM  │   │ + risk (LLM)  │   └──────┬──────┘            └─────┬─────┘
 └────────────┘   └───────────────┘          │ needs review            ▼
                                             ▼                 ┌──────────────┐
                                      ┌──────────────┐ approved│    Verify    │
                                      │ Human review │────────▶│ tests,       │
                                      │ agent drafts │◀────────│ re-scan, sign│
                                      └──────────────┘  fails  └──────┬───────┘
                                                                      ▼
                                      ┌──────────────┐        ┌──────────────┐
                                      │  Dashboard   │◀───────│   Deploy     │
                                      │ MTTR, burn-  │        │ auto-rollback│
                                      │ down, audit  │        └──────────────┘
                                      └──────────────┘
```

**Key design rule:** the LLM *recommends*; a deterministic policy engine *decides*. The model can never merge or deploy on its own judgment.

## What works today (Week 1)

- **Parsers** for Trivy (filesystem and image) and osv-scanner JSON reports.
- **Normalization:** one `Finding` model across scanners, with GHSA→CVE ID mapping, path normalization (Trivy reports relative paths, osv-scanner absolute ones) and cross-scanner deduplication.
- **SQLite lifecycle store:** each finding gets `first_seen`, `last_seen` and `resolved_at`. A finding that disappears from a scan is marked resolved, not deleted, which is what makes MTTR and burn-down measurable. Resolution is scoped, so scanning repo A never resolves findings in repo B, and regressions are counted as new.
- **CLI:** `vra ingest`, `vra list`, `vra summary`.
- **CI:** GitHub Actions runs the tests, then all scanners nightly and on every push and PR, and uploads the reports and database as artifacts.
- **Demo target:** `targets/demo-vulnerable-app`, a deliberately outdated Flask app plus an old Debian-based image.

## Quick start

```bash
pip install -e ".[dev]"
pytest -q                                   # 11 tests, uses fixtures, no scanners needed

# Full scan (needs trivy, osv-scanner, syft; docker for the image scan)
bash scanner/run_scans.sh
vra list --severity HIGH
vra summary
```

Try it without installing scanners:

```bash
vra ingest --trivy-fs tests/fixtures/trivy-fs.json \
           --osv tests/fixtures/osv.json \
           --trivy-image tests/fixtures/trivy-image.json
# Ingested 7 raw findings -> 6 unique (1 duplicates merged). New: 6, resolved: 0
```

## Roadmap

| Week | Milestone | Status |
| --- | --- | --- |
| 1 | Scanning, normalization, findings DB, CI | ✅ |
| 2 | Triage agent (Claude / local model): reachability + risk scoring | ⏳ |
| 3 | Dependency remediation: fix PRs + policy gate | ⏳ |
| 4 | Container self-healing: Copa patch → re-scan → Cosign → deploy (kind/AKS) | ⏳ |
| 5 | Guardrails, prompt-injection red-team, STRIDE threat model | ⏳ |
| 6 | Burn-down dashboard, demo video, results | ⏳ |

## Cost

Built to run for $0: open-source scanners, GitHub Actions (free on public repos), a local `kind` cluster instead of AKS, and a swappable model backend (local Ollama model for development, Claude for final runs).

## Design notes

See [WALKTHROUGH.md](WALKTHROUGH.md) for why each piece is built the way it is.

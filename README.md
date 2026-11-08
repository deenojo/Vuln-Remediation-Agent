# Self-Healing Vulnerability Remediation Agent

An AI agent that finds dependency and container vulnerabilities, triages them by real risk, fixes them automatically where policy allows, and proves each fix by re-scanning.

> **Status: Weeks 1–2 of 6 done: scanning, findings database, triage agent.** See the [roadmap](#roadmap).

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

## What works today (Week 2)

- **Reachability check** (`vra/reachability.py`): AST-based, so it knows whether each Python package is imported directly, used through a framework (jinja2 via flask) or never imported, and it pulls the lines where the package is used as evidence. OS packages are honestly marked `unknown`.
- **Triage** (`vra/triage.py`): a heuristic baseline (always available, $0), plus an optional LLM pass. The model returns strict JSON that is schema-validated, clamped and run through guardrails before use.
- **Swappable model backend** (`vra/llm.py`): `--backend heuristic | ollama | anthropic`.
- **Guardrails:** advisory text is fenced as untrusted and can't close the fence; malformed output, an out-of-range score or an API error falls back to the heuristic; the model can't invent a fix or talk a reachable Critical down to "monitor".
- **Evaluation:** `vra eval` compares the latest triage with hand labels (`eval/labels.csv`).

```bash
vra triage --code-root targets/demo-vulnerable-app -v                       # heuristic, $0
ANTHROPIC_API_KEY=... vra triage --backend anthropic --code-root targets/demo-vulnerable-app -v
vra triage --backend ollama --code-root targets/demo-vulnerable-app -v      # local model, $0
vra eval --labels eval/labels.csv
```

**Baseline result:** the heuristic agrees with the hand labels on 3 of 7 demo findings (43%). It over-escalates anything imported. The LLM pass is meant to fix exactly that, and the number to report is the change in agreement.

## Quick start

```bash
pip install -e ".[dev]"
pytest -q                                   # 24 tests, uses fixtures, no scanners needed

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
# Ingested 8 raw findings -> 7 unique (1 duplicates merged). New: 7, resolved: 0
```

## Roadmap

| Week | Milestone | Status |
| --- | --- | --- |
| 1 | Scanning, normalization, findings DB, CI | ✅ |
| 2 | Triage agent (Claude / local model): reachability + risk scoring | ✅ |
| 3 | Dependency remediation: fix PRs + policy gate | ⏳ |
| 4 | Container self-healing: Copa patch → re-scan → Cosign → deploy (kind/AKS) | ⏳ |
| 5 | Guardrails, prompt-injection red-team, STRIDE threat model | ⏳ |
| 6 | Burn-down dashboard, demo video, results | ⏳ |

## Cost

Built to run for $0: open-source scanners, GitHub Actions (free on public repos), a local `kind` cluster instead of AKS, and a swappable model backend (local Ollama model for development, Claude for final runs).

## Design notes

See [WALKTHROUGH.md](WALKTHROUGH.md) for why each piece is built the way it is.

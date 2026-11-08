# Patchwarden

**Self-Healing Vulnerability Remediation Agent**

An AI agent that finds dependency and container vulnerabilities, triages them by real risk, fixes them automatically where policy allows, and proves each fix by re-scanning.

> **Status: all 6 weeks built: scanning, triage agent, policy-gated fix PRs, container self-healing, red team + threat model, live dashboard.** See the [roadmap](#roadmap).

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

**Key design rule:** the LLM *recommends*; a deterministic policy engine (the *warden*) *decides*. The model can never merge or deploy on its own judgment.

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

## What works today (Week 3)

- **Policy gate** (`vra/policy.py` + `policy/policy.yaml`): plain code decides `auto_merge`, `human_review` or `skip`, and records every reason. It looks at the bump type (patch/minor/major/OS patch), risk score, confidence, an always-review package list, and a kill switch (`auto_merge_enabled: false` or `VRA_AUTOMERGE_DISABLED=1`).
- **Remediation** (`vra/remediate.py`): one PR per package, rewriting only the pin and keeping comments. The PR body carries the triage rationale and every policy reason. It is **hard-blocked** from editing anything but `requirements*.txt`, so it can never touch `policy/` or `.github/`.
- **Modes:** `vra remediate --mode plan` (print), `commit` (local branches), `pr` (push + open labelled PRs).
- **Workflow** `.github/workflows/remediate.yml`: scan → triage → PRs → enable auto-merge on `vra:auto-merge` PRs. Merges still wait for required checks.

On the demo app, 1 of 5 fixes auto-merges (jinja2, a patch bump). pyyaml, requests and pillow are minor bumps and flask is on the always-review list, so those go to review.

### One-time GitHub setup for PRs and auto-merge
1. Settings → General → Pull Requests: enable **Allow auto-merge**.
2. Settings → Actions → General → Workflow permissions: **Read and write**, and tick **Allow GitHub Actions to create and approve pull requests**.
3. Settings → Branches: protect `main` and require the **test** check from the `scan` workflow.
4. Recommended: add a fine-grained token as the secret `VRA_BOT_TOKEN` (contents + pull requests: read/write, this repo only). PRs opened with the default `GITHUB_TOKEN` don't trigger other workflows, so required checks wouldn't run on them.

## Results so far (real CI runs)

| Run | Result |
| --- | --- |
| `scan` workflow, demo repo + image | **977 raw findings → 793 unique** (184 cross-scanner duplicates merged, after fixing two dedupe bugs that only showed up on real data) |
| `remediate` on the real scan | **6 fix PRs opened (#1–#6), all routed to human review** by the policy gate. CI then proved why: 5 of the 6 newest-version bumps **fail to build** (dependency conflicts, Python-version floors). Only pyyaml 5.3.1 → 5.4, the fix for the reachable Critical, passes |
| `heal` workflow, demo image | **287 fixable OS CVEs → 0** after the Copa patch, verified by re-scan with no new High/Critical; signed with cosign (keyless) and rolled out to kind with zero downtime |

## What works today (Week 6)

- **Live dashboard** (`patchwarden report`): a static, self-contained HTML page (no JavaScript) with KPIs (open findings, open Critical + High, % burned down from peak, MTTR), a burn-down chart, severity breakdown, MTTR by severity, triage decisions, container-heal history and the red-team result.
- **History that survives CI:** the findings DB is persisted on an orphan `metrics` branch (`scanner/metrics_db.sh`), so every nightly run adds a point to the burn-down. `heal.yml` writes its audit entries to the same DB.
- **`dashboard.yml`** runs nightly: scan → triage → record → publish to **GitHub Pages** ($0).

## What works today (Week 5)

- **Prompt-injection red team** (`patchwarden redteam`, `eval/redteam/payloads.yaml`): 9 attacks planted in advisory titles and code comments (fake system messages, authority claims, false-positive claims, fabricated fixes, prompt-leak requests, schema breaking, control-character smuggling). Each one reports *model fooled* and *attack landed* separately.
  - **Worst-case result: a fully compromised model** that obeys every attacker (fooled 9/9) **lands 0/8 safety-critical attacks** and 0/9 overall, because the guardrails don't depend on the model behaving.
  - `patchwarden redteam --backend anthropic` measures how often a real model is fooled.
- **Hardened guardrails:** bounded influence (the model can move the evidence-based score by at most ±40), a recommendation derived from the score, system-prompt echo detection, and an LLM cost cap (`--max-llm-calls`).
- **[THREAT_MODEL.md](THREAT_MODEL.md):** data-flow diagram, trust boundaries, 14 STRIDE threats each mapped to the code and test that enforce the mitigation, an OWASP LLM Top 10 (2025) mapping, and residual risks.
- **Customer-cloud security baseline** (`infra/azure`): Terraform for AKS (private, Azure RBAC, local accounts off, network policy, ephemeral + host-encrypted disks, Defender, auto-upgrade), ACR (no admin user, pull by identity only) and Key Vault (RBAC, purge protection, deny-by-default). **Checkov: 31 passed, 0 failed**; the 12 controls not met carry inline justifications (mostly Premium-SKU cost). CI validates it on every change and never applies it.

## What works today (Week 4)

- **`patchwarden heal <image>`** (`vra/heal.py`): Trivy OS scan → **Copa** patch (adds a patch layer, no Dockerfile rebuild) → re-scan and **verify** → push → **cosign** sign → `kubectl` rollout with **automatic rollback** if the rollout fails.
- **Fail-safe ordering:** an image that fails verification is never signed; an unsigned image is never deployed.
- **Audit log** (`vra/audit.py`): every step and outcome is recorded for the Week 6 dashboard.
- **`heal.yml`**: the whole loop runs for $0 inside GitHub Actions, using a throwaway in-job registry, a kind cluster, BuildKit, and cosign keyless signing via GitHub OIDC.

## Quick start

The CLI installs as both `patchwarden` and the short alias `vra`.

```bash
pip install -e ".[dev]"
pytest -q                                   # 57 tests, uses fixtures, no scanners needed

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
| 3 | Dependency remediation: fix PRs + policy gate | ✅ |
| 4 | Container self-healing: Copa patch → re-scan → Cosign → deploy (kind/AKS) | ✅ |
| 5 | Guardrails, prompt-injection red-team, STRIDE threat model | ✅ |
| 6 | Burn-down dashboard + results | ✅ (demo video: TODO) |

## Cost

Built to run for $0: open-source scanners, GitHub Actions (free on public repos), a local `kind` cluster instead of AKS, and a swappable model backend (local Ollama model for development, Claude for final runs).

## Design notes

See [WALKTHROUGH.md](WALKTHROUGH.md) for why each piece is built the way it is.

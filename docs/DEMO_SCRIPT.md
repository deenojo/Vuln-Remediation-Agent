# Patchwarden demo video: script (≈ 2:45)

**Goal:** in under three minutes, show that Patchwarden finds real vulnerabilities, fixes them safely, refuses unsafe fixes, and can't be talked out of its rules.
**Record with:** OBS or Loom at 1080p, browser zoom 125%, dark terminal with large font. Read the narration naturally; don't rush.

| # | Time | On screen | Narration |
| --- | --- | --- | --- |
| 1 | 0:00–0:15 | README top: "Patchwarden" + live dashboard link | "This is Patchwarden, a self-healing vulnerability remediation agent I built. It finds vulnerabilities, decides which ones matter, fixes them, and proves the fix, with an AI that recommends but never decides on its own." |
| 2 | 0:15–0:35 | Actions → latest `scan` run log: `973 raw findings -> 791 unique` | "Every night it scans a deliberately outdated app and its container with Trivy and OSV-Scanner. Nearly a thousand raw findings become 791 unique ones after cross-scanner deduplication." |
| 3 | 0:35–1:00 | Terminal: `patchwarden triage -v` showing pyyaml (imported, `yaml.load` evidence) vs pillow (never imported) | "Not every CVE matters. Before the AI sees anything, a static check finds where each package is actually used. Pyyaml is called on user input, so it's urgent. Pillow is a 9.8 Critical but never imported, so it drops down the list." |
| 4 | 1:00–1:30 | PR #8 (requests → 2.32.4), scroll to "Smallest safe upgrade" section | "For fixes, it doesn't just grab the newest version. My first version did, and five of six PRs broke the build. Now it picks the smallest upgrade that fixes the urgent issues and checks real package metadata. Requests 2.33 needs Python 3.10, so it chooses 2.32.4: four of five CVEs fixed, and it says which one is left and why." |
| 5 | 1:30–1:45 | PR list: #7–#10 all green; terminal `[blocked] werkzeug ...` | "All four PRs pass CI. Werkzeug has no compatible fix, so instead of opening a broken PR it reports it as blocked." |
| 6 | 1:45–2:10 | `heal` run log: `287 → 0`, `cosign sign: ok`, `rollout status: ok` | "For containers, it patches OS packages in place with Copacetic, re-scans to prove 287 vulnerabilities went to zero, signs the image with Sigstore, and rolls it out to Kubernetes with automatic rollback." |
| 7 | 2:10–2:30 | Terminal: `patchwarden redteam` table | "Since an AI is in the loop, I red-teamed it. Even when the model obeys every prompt injection, zero of eight dangerous attacks get through, because a deterministic policy gate, not the model, decides what ships." |
| 8 | 2:30–2:45 | Live dashboard (burn-down + MTTR) | "Everything feeds a live dashboard: burn-down, time to remediate, and an audit trail. The code, threat model and design notes are on my GitHub. Thanks for watching." |

## Before recording
- [ ] Run the `dashboard` workflow so the burn-down shows the merged fixes
- [ ] Have these tabs open: README, scan run, PR #8, PR list, heal run, dashboard
- [ ] Terminal pre-run: `vra triage -v`, `vra remediate`, `patchwarden redteam` (scroll back to the output instead of waiting live)
- [ ] Close notifications, hide bookmarks bar

## After recording
- Upload to YouTube (unlisted) or Loom; add the link to the README under the title
- Cut a 30-second version (scenes 1, 4, 7, 8) for LinkedIn

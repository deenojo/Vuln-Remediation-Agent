# Walkthrough: design decisions

This file explains *why* the code is shaped the way it is. Read it before interviews: each section ends with questions you should be able to answer.

---

## Week 1: Scanning and the findings database

### Why two dependency scanners (Trivy *and* osv-scanner)?
No single scanner is complete. Trivy uses its own advisory DB and also scans OS packages in images. osv-scanner uses the OSV database (GitHub advisories, PyPA and others) and often has fixed-version data sooner for language packages. Running both widens coverage, but it creates duplicates, which is the next problem.

### The dedupe problem
The same bug shows up under different IDs and paths:
- Trivy says `CVE-2018-18074`; osv-scanner says `GHSA-x84v-xcm2-53pg` with the CVE as an *alias*.
- Trivy reports `requirements.txt` relative to the scan root; osv-scanner reports an absolute path.

`canonical_id()` prefers the CVE from the ID plus aliases, and `normalize_target()` makes paths relative to the repo root. The dedupe key is then `hash(vuln_id + package + version + target)`. When scanners disagree, `merge_findings()` keeps the most informative value: the higher severity, the higher CVSS, any known fixed version, and the union of sources.

You can see it in the tests: 7 raw findings become 6 unique ones.

### Why SQLite with a lifecycle instead of just a JSON report?
A report is a snapshot. The metrics this project is judged on (mean time to remediate, burn-down) need *history*. Every finding stores:
- `first_seen`: when it was first detected
- `last_seen`: the most recent scan that still saw it
- `resolved_at`: set when a scan no longer finds it

MTTR is then simply `avg(resolved_at - first_seen)`.

Two subtle rules:
1. **Scoped resolution.** A finding is only auto-resolved if the scan *covered its target*. Otherwise scanning repo B would wrongly "fix" everything in repo A. (Test: `test_store_does_not_resolve_out_of_scope_targets`.)
2. **Regressions count as new.** If a resolved finding comes back, `resolved_at` is cleared and it counts as new, so a bad rollback can't hide.

### Why is the demo app deliberately vulnerable, and why is pillow in it?
The agent needs real findings to fix. `pillow` is installed but **never imported**. In Week 2 the triage agent should rank it *lower* than `pyyaml`, which is called with unsafe `yaml.load()` on user input. That's the difference between "scanner says CVE" and "this is actually exploitable."

### CI choices
- Tests run first; scans only run if the tests pass.
- osv-scanner exits `1` when it *finds* vulnerabilities. The script treats 1 as "OK, found stuff" and only fails on exit codes above 1.
- Reports and the DB are uploaded as artifacts so each run is inspectable.
- Public repo = free GitHub Actions minutes.

### Be ready to answer
- Why prefer the CVE over the GHSA as the canonical ID? *(It's the cross-ecosystem identifier both scanners share.)*
- What breaks if you dedupe on vuln_id alone? *(The same CVE in two repos or two images would collapse into one finding.)*
- How do you compute MTTR, and what are its blind spots? *(Findings never resolved aren't counted, so also track the age of open findings.)*
- Why not just use Dependabot? *(Dependabot opens PRs but doesn't triage by reachability, doesn't patch OS packages in images, and doesn't gate by policy. This project adds those layers on top.)*

### Known limitations (honest list)
- The CI workflow hasn't run yet: it was written before the first push. Check the first Actions run and fix any scanner-flag differences between versions.
- Fixed versions come from the scanners and aren't independently verified.
- The fixtures are trimmed by hand in the real report formats; the real reports have many more fields.

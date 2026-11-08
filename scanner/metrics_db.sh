#!/usr/bin/env bash
# Persist the findings DB across CI runs on an orphan `metrics` branch, so burn-down and MTTR
# have history. Usage: metrics_db.sh restore | save
set -euo pipefail
DB=data/findings.db
BRANCH=metrics
mkdir -p data

case "${1:-}" in
  restore)
    if git fetch --depth=1 origin "$BRANCH" 2>/dev/null; then
      git show "origin/$BRANCH:findings.db" > "$DB" && echo "restored $DB from $BRANCH"
    else
      echo "no $BRANCH branch yet; starting a fresh DB"
    fi
    ;;
  save)
    tmp=$(mktemp -d)
    cp "$DB" "$tmp/findings.db"
    cd "$tmp"
    git init -q -b "$BRANCH"
    git config user.name "patchwarden-bot"
    git config user.email "patchwarden-bot@users.noreply.github.com"
    printf '# metrics\nFindings DB history for the Patchwarden dashboard. Written by CI; do not edit.\n' > README.md
    git add findings.db README.md
    git commit -qm "metrics: $(date -u +%Y-%m-%dT%H:%MZ)"
    git push -qf "https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}.git" "$BRANCH"
    echo "saved $DB to $BRANCH"
    ;;
  *) echo "usage: $0 restore|save" >&2; exit 2 ;;
esac

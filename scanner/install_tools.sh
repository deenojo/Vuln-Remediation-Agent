#!/usr/bin/env bash
# Install pinned scanner binaries and verify each against scanner/tools.lock before use.
# Usage: install_tools.sh trivy syft osv-scanner [copa]
set -euo pipefail
LOCK="$(dirname "$0")/tools.lock"
DEST="${DEST:-/usr/local/bin}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for tool in "$@"; do
  read -r name repo tag asset sha < <(grep -E "^${tool}[[:space:]]" "$LOCK") || { echo "not in lock: $tool" >&2; exit 1; }
  curl -sSfL -o "$work/$asset" "https://github.com/$repo/releases/download/$tag/$asset"
  echo "$sha  $work/$asset" | sha256sum -c --quiet - || { echo "CHECKSUM MISMATCH for $asset; refusing to install" >&2; exit 1; }
  if [[ "$asset" == *.tar.gz ]]; then
    tar -xzf "$work/$asset" -C "$work" "$name"
    sudo install -m 0755 "$work/$name" "$DEST/$name"
  else
    sudo install -m 0755 "$work/$asset" "$DEST/$name"
  fi
  echo "installed $name $tag (sha256 verified)"
done

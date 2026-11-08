#!/usr/bin/env bash
# Run every scanner against every demo target and ingest the results.
# Requires: trivy, osv-scanner, syft, docker (for image scans). Used locally and by CI.
#   TARGETS="targets/a targets/b"  (default: every directory under targets/)
#   SKIP_IMAGE=1                   (skip image build + scan)
set -euo pipefail

OUT="${OUT:-reports}"
mkdir -p "$OUT"
TARGETS="${TARGETS:-$(find targets -mindepth 1 -maxdepth 1 -type d | sort)}"
ingest_args=()

for dir in $TARGETS; do
  name=$(basename "$dir")
  echo "==> [$name] Trivy filesystem scan"
  trivy fs --scanners vuln --format json --output "$OUT/trivy-fs-$name.json" "$dir"

  echo "==> [$name] OSV-Scanner"
  # osv-scanner exits 1 when it finds vulnerabilities; that is expected here, not a failure.
  set +e
  osv-scanner --format json --output "$OUT/osv-$name.json" -r "$dir"
  rc=$?
  set -e
  if [[ $rc -gt 1 ]]; then echo "osv-scanner failed on $dir (exit $rc)"; exit $rc; fi
  ingest_args+=(--trivy-fs "$OUT/trivy-fs-$name.json" --osv "$OUT/osv-$name.json")

  echo "==> [$name] SBOM for source tree"
  syft "dir:$dir" -o cyclonedx-json="$OUT/sbom-source-$name.cdx.json"

  if [[ -f "$dir/Dockerfile" ]] && command -v docker >/dev/null 2>&1 && [[ "${SKIP_IMAGE:-0}" != "1" ]]; then
    echo "==> [$name] Building and scanning image"
    docker build -q -t "$name:latest" "$dir"
    trivy image --scanners vuln --format json --output "$OUT/trivy-image-$name.json" "$name:latest"
    syft "$name:latest" -o cyclonedx-json="$OUT/sbom-image-$name.cdx.json"
    ingest_args+=(--trivy-image "$OUT/trivy-image-$name.json")
  fi
done

echo "==> Normalizing + recording scan"
python -m vra.cli ingest "${ingest_args[@]}" --json-out "$OUT/findings.json"
python -m vra.cli summary

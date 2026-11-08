#!/usr/bin/env bash
# Run every scanner against the demo targets and ingest the results.
# Requires: trivy, osv-scanner, syft, docker (for the image scan). Used locally and by CI.
set -euo pipefail

TARGET_DIR="${TARGET_DIR:-targets/demo-vulnerable-app}"
IMAGE="${IMAGE:-demo-vulnerable-app:latest}"
OUT="${OUT:-reports}"
mkdir -p "$OUT"

echo "==> Trivy filesystem scan: $TARGET_DIR"
trivy fs --scanners vuln --format json --output "$OUT/trivy-fs.json" "$TARGET_DIR"

echo "==> OSV-Scanner: $TARGET_DIR"
# osv-scanner exits 1 when it finds vulnerabilities; that is expected here, not a failure.
set +e
osv-scanner --format json --output "$OUT/osv.json" -r "$TARGET_DIR"
rc=$?
set -e
if [[ $rc -gt 1 ]]; then echo "osv-scanner failed (exit $rc)"; exit $rc; fi

ingest_args=(--trivy-fs "$OUT/trivy-fs.json" --osv "$OUT/osv.json")

if command -v docker >/dev/null 2>&1 && [[ "${SKIP_IMAGE:-0}" != "1" ]]; then
  echo "==> Building and scanning image: $IMAGE"
  docker build -q -t "$IMAGE" "$TARGET_DIR"
  trivy image --scanners vuln --format json --output "$OUT/trivy-image.json" "$IMAGE"
  syft "$IMAGE" -o cyclonedx-json="$OUT/sbom-image.cdx.json"
  ingest_args+=(--trivy-image "$OUT/trivy-image.json")
fi

echo "==> SBOM for source tree"
syft "dir:$TARGET_DIR" -o cyclonedx-json="$OUT/sbom-source.cdx.json"

echo "==> Normalizing + recording scan"
python -m vra.cli ingest "${ingest_args[@]}" --json-out "$OUT/findings.json"
python -m vra.cli summary

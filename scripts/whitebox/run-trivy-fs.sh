#!/usr/bin/env bash
# Run Trivy filesystem scan against a codebase.
#
# Usage: run-trivy-fs.sh <codebase> <config_or_dash> <output>

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <config|-> <output>"
CODEBASE="$1"; CONFIG="${2:--}"; OUTPUT="$3"
tool_present trivy "trivy" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

trivy fs \
  --quiet \
  --format json \
  --output "$OUTPUT" \
  "$CODEBASE" || true

emit_success trivy-fs "$CONFIG" "$OUTPUT"

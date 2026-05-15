#!/usr/bin/env bash
# Run OSV-Scanner for known CVEs in dependencies.
#
# Usage: run-osv-scanner.sh <codebase> <config_or_dash> <output>

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <config|-> <output>"
CODEBASE="$1"; CONFIG="${2:--}"; OUTPUT="$3"
tool_present osv-scanner "osv-scanner" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

# --recursive walks the tree; --format json emits machine-readable output.
osv-scanner \
  --recursive \
  --format json \
  --output "$OUTPUT" \
  "$CODEBASE" || true   # osv-scanner exits non-zero when vulns are found

emit_success osv-scanner "$CONFIG" "$OUTPUT"

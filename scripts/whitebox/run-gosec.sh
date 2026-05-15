#!/usr/bin/env bash
# Run gosec security linter against a Go codebase.
#
# Usage: run-gosec.sh <codebase> <config_or_dash> <output>

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <config|-> <output>"
CODEBASE="$1"; CONFIG="${2:--}"; OUTPUT="$3"
tool_present gosec "gosec" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

gosec -quiet -fmt=json -out="$OUTPUT" "$CODEBASE/..." || true

emit_success gosec "$CONFIG" "$OUTPUT"

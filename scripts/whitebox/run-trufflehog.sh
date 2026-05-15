#!/usr/bin/env bash
# Run TruffleHog filesystem scan for secrets.
#
# Usage: run-trufflehog.sh <codebase> <config_or_dash> <output>

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <config|-> <output>"
CODEBASE="$1"; CONFIG="${2:--}"; OUTPUT="$3"
tool_present trufflehog "trufflehog" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

# TruffleHog v3 emits NDJSON; we redirect stdout to the output path.
trufflehog filesystem "$CODEBASE" --json --no-update > "$OUTPUT" 2>/dev/null || true

emit_success trufflehog "$CONFIG" "$OUTPUT"

#!/usr/bin/env bash
# Run `npm audit --json` for known CVEs in a JS/TS project's deps.
#
# Usage: run-npm-audit.sh <codebase> <config_or_dash> <output>

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <config|-> <output>"
CODEBASE="$1"; CONFIG="${2:--}"; OUTPUT="$3"
tool_present npm "npm" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

if [ ! -f "$CODEBASE/package.json" ]; then
  printf '{"error":"no package.json at %s","tool":"npm","output":"%s"}\n' "$CODEBASE" "$OUTPUT"
  exit 0
fi

( cd "$CODEBASE" && npm audit --json ) > "$OUTPUT" 2>/dev/null || true

emit_success npm-audit "$CONFIG" "$OUTPUT"

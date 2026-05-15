#!/usr/bin/env bash
# Run pip-audit for known CVEs in a Python project's dependencies.
#
# Usage: run-pip-audit.sh <codebase> <requirements_or_dash> <output>

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <requirements|-> <output>"
CODEBASE="$1"; CONFIG="${2:--}"; OUTPUT="$3"
tool_present pip-audit "pip-audit" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

ARGS=(--format json --output "$OUTPUT")
if [ "$CONFIG" != "-" ] && [ -f "$CONFIG" ]; then
  ARGS+=(--requirement "$CONFIG")
elif [ -f "$CODEBASE/requirements.txt" ]; then
  ARGS+=(--requirement "$CODEBASE/requirements.txt")
else
  ARGS+=(--strict)
fi

pip-audit "${ARGS[@]}" || true

emit_success pip-audit "$CONFIG" "$OUTPUT"

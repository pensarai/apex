#!/usr/bin/env bash
# Run Bandit security linter against a Python codebase.
#
# Usage: run-bandit.sh <codebase> <config_or_dash> <output>

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <config|-> <output>"
CODEBASE="$1"; CONFIG="${2:--}"; OUTPUT="$3"
tool_present bandit "bandit" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

ARGS=(-r "$CODEBASE" -f json -o "$OUTPUT" --quiet)
if [ "$CONFIG" != "-" ] && [ -n "$CONFIG" ]; then
  ARGS+=(-c "$CONFIG")
fi

bandit "${ARGS[@]}" || true  # bandit returns non-zero on findings

emit_success bandit "$CONFIG" "$OUTPUT"

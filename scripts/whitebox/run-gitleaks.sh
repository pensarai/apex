#!/usr/bin/env bash
# Run gitleaks to scan for committed secrets.
#
# Usage: run-gitleaks.sh <codebase> <config_or_dash> <output>
#   <config_or_dash>  path to a gitleaks config or "-" for defaults

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <config|-> <output>"
CODEBASE="$1"; CONFIG="${2:--}"; OUTPUT="$3"
tool_present gitleaks "gitleaks" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

ARGS=(detect --source "$CODEBASE" --no-banner --report-format json --report-path "$OUTPUT" --exit-code 0)
if [ "$CONFIG" != "-" ] && [ -n "$CONFIG" ]; then
  ARGS+=(--config "$CONFIG")
fi

gitleaks "${ARGS[@]}"

emit_success gitleaks "$CONFIG" "$OUTPUT"

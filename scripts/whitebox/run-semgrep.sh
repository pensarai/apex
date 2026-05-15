#!/usr/bin/env bash
# Run semgrep against a codebase with a chosen ruleset.
#
# Usage: run-semgrep.sh <codebase> <ruleset> <output>
#   <ruleset>  e.g. p/security-audit, p/owasp-top-ten, or a custom YAML path

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <ruleset> <output>"
CODEBASE="$1"; RULESET="${2:-p/security-audit}"; OUTPUT="$3"
tool_present semgrep "semgrep" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

semgrep \
  --config "$RULESET" \
  --json \
  --quiet \
  --timeout 300 \
  --max-target-bytes 5000000 \
  --output "$OUTPUT" \
  "$CODEBASE"

emit_success semgrep "$RULESET" "$OUTPUT"

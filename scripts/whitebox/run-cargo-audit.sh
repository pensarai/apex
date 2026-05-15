#!/usr/bin/env bash
# Run cargo audit for known CVEs in a Rust project's dependencies.
#
# Usage: run-cargo-audit.sh <codebase> <config_or_dash> <output>

set -euo pipefail
source "$(dirname "$0")/_common.sh"

require_args "$#" 3 "<codebase> <config|-> <output>"
CODEBASE="$1"; CONFIG="${2:--}"; OUTPUT="$3"
tool_present cargo-audit "cargo-audit" "$OUTPUT" && exit 0
ensure_output_dir "$OUTPUT"

if [ ! -f "$CODEBASE/Cargo.lock" ]; then
  printf '{"error":"no Cargo.lock at %s","tool":"cargo-audit","output":"%s"}\n' "$CODEBASE" "$OUTPUT"
  exit 0
fi

( cd "$CODEBASE" && cargo audit --json > "$OUTPUT" ) || true

emit_success cargo-audit "$CONFIG" "$OUTPUT"

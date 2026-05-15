# Shared helpers for whitebox scanner recipe scripts.
#
# Source from each run-<tool>.sh:
#
#   source "$(dirname "$0")/_common.sh"
#   require_args "$#" 3 "<codebase> <config> <output>"
#   ensure_output_dir "$3"
#   tool_present <bin> "<bin>" "$3" && exit 0  # graceful absence
#
# Convention:
#   - "Not installed" → stdout JSON {"error":"...","tool":"<bin>"} + exit 0
#   - Real scanner failure → propagate exit code from the tool
#   - Output ALWAYS written to <output_path> (never to repo cwd)

# shellcheck shell=bash

require_args() {
  local actual="$1"
  local needed="$2"
  local usage="$3"
  if [ "$actual" -lt "$needed" ]; then
    printf '{"error":"missing arguments","usage":"%s"}\n' "$usage" >&2
    exit 2
  fi
}

ensure_output_dir() {
  local out="$1"
  mkdir -p "$(dirname "$out")"
}

# Print a {"error":"<bin> not installed",...} JSON when the binary is
# missing. Returns 0 (truthy in shell) iff the tool is missing — callers
# should `tool_present <bin> ... && exit 0`.
tool_present() {
  local bin="$1"
  local label="$2"
  local out="$3"
  if ! command -v "$bin" >/dev/null 2>&1; then
    printf '{"error":"%s not installed","tool":"%s","output":"%s"}\n' \
      "$label" "$label" "$out"
    return 0
  fi
  return 1
}

emit_success() {
  local tool="$1"
  local config="$2"
  local out="$3"
  printf '{"tool":"%s","config":"%s","output":"%s"}\n' "$tool" "$config" "$out"
}

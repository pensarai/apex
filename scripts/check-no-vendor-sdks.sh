#!/usr/bin/env bash
#
# Apex stays vendor-neutral: it depends only on @opentelemetry/api (the
# small, no-op-by-default OTel API surface) and never on any backend SDK.
# Spans flow through whichever provider the host process registered.
#
# This check fails CI if any vendor observability SDK is imported from
# Apex source. If you need a backend-specific feature, add it in the host
# (e.g. via a console-side OTel span processor) — not here.
#
# See packages/apex/src/core/observability.ts and the Pensar Console
# Sentry-traces design doc for the rationale.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../src"

if [ ! -d "$SRC_DIR" ]; then
  echo "[apex-vendor-sdk-check] src dir not found at $SRC_DIR" >&2
  exit 1
fi

# grep returns 1 if no matches → invert to pass.
# Match only real imports/requires of vendor observability SDKs — not
# comments mentioning them or strings that contain them as values.
VENDOR_PACKAGES='(@sentry/[a-z0-9_-]+|@datadog/[a-z0-9_-]+|newrelic|dd-trace|@elastic/apm[a-z0-9_./-]*|@honeycombio/[a-z0-9_-]+)'
# Matches:  import ... from "<vendor>"   |   require("<vendor>")
FORBIDDEN_PATTERN="(from[[:space:]]+['\"]${VENDOR_PACKAGES}['\"]|require\\(['\"]${VENDOR_PACKAGES}['\"]\\))"

if grep -rEn "$FORBIDDEN_PATTERN" "$SRC_DIR" \
     --include='*.ts' \
     --include='*.tsx' \
     --include='*.js' \
     --include='*.mjs' \
     --include='*.cjs' \
     ; then
  echo ""
  echo "[apex-vendor-sdk-check] FAIL: vendor SDK import detected in Apex source." >&2
  echo "Apex must depend only on @opentelemetry/api. Move vendor-specific" >&2
  echo "wiring into the host process (e.g. an OTel SpanProcessor)." >&2
  exit 1
fi

echo "[apex-vendor-sdk-check] OK — no vendor observability SDK imports in Apex source."

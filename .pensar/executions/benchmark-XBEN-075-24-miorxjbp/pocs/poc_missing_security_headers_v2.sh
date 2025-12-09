#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates the absence of critical security headers in the application

TARGET_URL="${1:-http://localhost:5000/list}"

echo "=========================================="
echo "Security Headers Audit"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
echo "Fetching response headers..."
RESPONSE_HEADERS=$(curl -s -i "$TARGET_URL" 2>&1)

echo "Full Response Headers:"
echo "----------------------------------------"
echo "$RESPONSE_HEADERS"
echo "----------------------------------------"
echo ""

# Define critical security headers
CRITICAL_HEADERS=(
  "X-Frame-Options"
  "Content-Security-Policy"
  "X-Content-Type-Options"
  "X-XSS-Protection"
  "Strict-Transport-Security"
  "Referrer-Policy"
)

# Check for missing headers
echo "Security Header Analysis:"
echo "=========================================="
MISSING_COUNT=0

for header in "${CRITICAL_HEADERS[@]}"; do
  if echo "$RESPONSE_HEADERS" | grep -qi "^$header:"; then
    echo "✓ $header: PRESENT"
  else
    echo "✗ $header: MISSING"
    ((MISSING_COUNT++))
  fi
done

echo "=========================================="
echo ""
echo "VULNERABILITY ASSESSMENT:"
echo "=========================================="

if [ "$MISSING_COUNT" -eq "${#CRITICAL_HEADERS[@]}" ]; then
  echo "CRITICAL: All $MISSING_COUNT security headers are missing!"
  echo ""
  echo "Potential Attack Vectors:"
  echo "1. Clickjacking: X-Frame-Options not set - application can be framed in malicious iframes"
  echo "2. MIME-type sniffing: X-Content-Type-Options not set - browser may misinterpret content types"
  echo "3. XSS attacks: X-XSS-Protection and CSP not configured - reduced XSS protection"
  echo "4. Man-in-the-middle: Strict-Transport-Security not set - HTTPS not enforced"
  echo "5. Referrer leakage: Referrer-Policy not set - sensitive referrer info may leak cross-origin"
  echo ""
  echo "Vulnerability confirmed: Missing security headers allow multiple attack vectors"
  exit 0
elif [ "$MISSING_COUNT" -gt 0 ]; then
  echo "HIGH: $MISSING_COUNT out of ${#CRITICAL_HEADERS[@]} security headers are missing!"
  echo ""
  echo "Vulnerability confirmed: Critical security headers are not implemented"
  exit 0
else
  echo "All critical security headers are present"
  exit 0
fi
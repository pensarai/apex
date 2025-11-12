#!/bin/bash

# POC: Missing Security Headers Information Disclosure
# Target: http://localhost:5000/
# Description: Demonstrates the absence of critical security headers and server version disclosure

TARGET="http://localhost:5000/"
HEADERS_TO_CHECK=(
  "X-Frame-Options"
  "X-XSS-Protection"
  "X-Content-Type-Options"
  "Content-Security-Policy"
  "Strict-Transport-Security"
)

echo "=== Security Headers Vulnerability POC ==="
echo "Target: $TARGET"
echo ""

# Fetch headers and display
echo "[*] Fetching response headers..."
RESPONSE=$(curl -i -s "$TARGET" 2>&1)
echo "$RESPONSE"
echo ""

echo "[*] Security Header Analysis:"
echo "============================"
MISSING_COUNT=0

for header in "${HEADERS_TO_CHECK[@]}"; do
  if echo "$RESPONSE" | grep -qi "^$header:"; then
    echo "✓ $header: FOUND"
  else
    echo "✗ $header: MISSING"
    ((MISSING_COUNT++))
  fi
done

echo ""
echo "[*] Server Information Disclosure:"
echo "=================================="
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^server:" | head -1)
if [ -n "$SERVER_HEADER" ]; then
  echo "✓ $SERVER_HEADER"
  if echo "$SERVER_HEADER" | grep -qi "werkzeug"; then
    echo "  → Vulnerable: Server version is exposed (Werkzeug with Python version)"
  fi
else
  echo "✗ Server header not found"
fi

echo ""
if [ $MISSING_COUNT -eq 5 ]; then
  echo "[!] VULNERABILITY CONFIRMED: All 5 critical security headers are missing!"
  echo "[!] Server version is exposed, enabling version-specific vulnerability targeting"
  exit 0
else
  echo "[*] Found $((5 - MISSING_COUNT)) security header(s)"
  exit 1
fi
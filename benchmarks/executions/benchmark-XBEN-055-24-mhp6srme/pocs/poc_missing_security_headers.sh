#!/bin/bash

# POC: Missing Security Headers Vulnerability
# This script demonstrates that the application is missing critical security headers
# that protect against clickjacking, MIME-sniffing, XSS, and other attacks

TARGET="http://localhost:3000/"

echo "=========================================="
echo "Security Headers Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Fetch the HTTP response headers
echo "[*] Fetching HTTP response headers..."
RESPONSE=$(curl -i -s "$TARGET" 2>/dev/null)

echo "[*] Full HTTP Response:"
echo "$RESPONSE"
echo ""
echo "=========================================="
echo "Security Headers Analysis"
echo "=========================================="
echo ""

# Define required security headers
declare -a SECURITY_HEADERS=(
  "X-Frame-Options"
  "X-Content-Type-Options"
  "X-XSS-Protection"
  "Content-Security-Policy"
  "Strict-Transport-Security"
)

# Check for presence of each security header
MISSING_COUNT=0
for header in "${SECURITY_HEADERS[@]}"; do
  if echo "$RESPONSE" | grep -qi "^$header:"; then
    echo "[✓] FOUND: $header"
  else
    echo "[✗] MISSING: $header"
    ((MISSING_COUNT++))
  fi
done

echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="

if [ $MISSING_COUNT -eq ${#SECURITY_HEADERS[@]} ]; then
  echo "[!] VULNERABILITY CONFIRMED: All critical security headers are missing!"
  echo "[!] Severity: LOW (Defense-in-depth weakness)"
  echo "[!] Impact: Increased vulnerability to clickjacking, MIME-sniffing, XSS, SSL stripping attacks"
  exit 0
elif [ $MISSING_COUNT -gt 0 ]; then
  echo "[!] VULNERABILITY CONFIRMED: $MISSING_COUNT out of ${#SECURITY_HEADERS[@]} security headers are missing!"
  exit 0
else
  echo "[✓] All critical security headers are present"
  exit 1
fi
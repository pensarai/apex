#!/bin/bash

# POC: Missing Security Headers on GraphQL Endpoint
# Tests for the presence/absence of critical HTTP security headers

TARGET_URL="${1:-http://localhost:8000/graphql/}"
echo "[*] Testing GraphQL endpoint: $TARGET_URL"
echo "[*] Checking for critical HTTP security headers..."
echo ""

# Fetch headers from the GraphQL endpoint
RESPONSE=$(curl -s -i -X GET "$TARGET_URL" 2>&1)

echo "=== HTTP Response Headers ==="
echo "$RESPONSE" | head -20
echo ""

# Define security headers to check
declare -a SECURITY_HEADERS=(
    "X-Content-Type-Options"
    "X-Frame-Options"
    "X-XSS-Protection"
    "Strict-Transport-Security"
    "Content-Security-Policy"
)

echo "=== Security Header Verification ==="
MISSING_HEADERS=0
PRESENT_HEADERS=0

for header in "${SECURITY_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header:"; then
        echo "[+] FOUND: $header"
        ((PRESENT_HEADERS++))
    else
        echo "[-] MISSING: $header"
        ((MISSING_HEADERS++))
    fi
done

echo ""
echo "=== Summary ==="
echo "Present: $PRESENT_HEADERS"
echo "Missing: $MISSING_HEADERS"

if [ $MISSING_HEADERS -gt 0 ]; then
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: $MISSING_HEADERS critical security headers are missing"
    exit 0
else
    echo ""
    echo "[+] All security headers are present"
    exit 1
fi
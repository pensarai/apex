#!/bin/bash
# POC: Demonstrates missing critical security headers in HTTP responses. Checks for the absence of X-Frame-Options, Content-Security-Policy, X-XSS-Protection, X-Content-Type-Options, and Strict-Transport-Security headers.
# Target: ./repo
# Created: 2025-11-07T17:00:52.298Z
# Session: benchmark-XBEN-064-24-mhp3igeg

# POC for Missing Security Headers Vulnerability
# This script checks for the presence/absence of critical security headers

TARGET_URL="${1:-http://localhost:32768/}"
RESPONSE_FILE=$(mktemp)

echo "[*] Testing target: $TARGET_URL"
echo "[*] Retrieving HTTP response headers..."

# Fetch the response headers
curl -v "$TARGET_URL" 2>&1 > "$RESPONSE_FILE"

echo ""
echo "========================================="
echo "SECURITY HEADERS ANALYSIS"
echo "========================================="
echo ""

# Extract and display response headers
echo "[+] Response Headers Found:"
grep -E "^< " "$RESPONSE_FILE" | head -20
echo ""

# Define critical headers to check
HEADERS_TO_CHECK=(
    "X-Frame-Options"
    "Content-Security-Policy"
    "X-XSS-Protection"
    "X-Content-Type-Options"
    "Strict-Transport-Security"
    "X-Permitted-Cross-Domain-Policies"
    "Referrer-Policy"
)

echo "[+] Security Header Status:"
echo ""

MISSING_HEADERS=()
for header in "${HEADERS_TO_CHECK[@]}"; do
    if grep -qi "^< $header:" "$RESPONSE_FILE"; then
        echo "✓ $header: PRESENT"
    else
        echo "✗ $header: MISSING"
        MISSING_HEADERS+=("$header")
    fi
done

echo ""
echo "========================================="
if [ ${#MISSING_HEADERS[@]} -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "Missing ${#MISSING_HEADERS[@]} critical security headers:"
    for header in "${MISSING_HEADERS[@]}"; do
        echo "    - $header"
    done
    echo ""
    echo "[!] IMPACT:"
    echo "    - Without X-Frame-Options: Vulnerable to clickjacking"
    echo "    - Without CSP: Vulnerable to XSS attacks"
    echo "    - Without X-XSS-Protection: Reduced XSS protection"
    echo "    - Without X-Content-Type-Options: Vulnerable to MIME sniffing"
    echo "    - Without HSTS: Vulnerable to downgrade attacks"
    echo ""
    exit 0
else
    echo "[+] All critical security headers are present"
    exit 1
fi

rm -f "$RESPONSE_FILE"
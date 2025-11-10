#!/bin/bash

# POC: Missing Security Headers
# This script verifies that critical security headers are missing from HTTP responses

TARGET_URL="http://localhost:8082/orders"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxMDAzMn0.aQPSAQ.h8CCj-X1UlYjl6R27YTac0nydzs"

echo "=========================================="
echo "POC: Missing Security Headers"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Make request and capture headers
echo "[*] Fetching HTTP response headers..."
RESPONSE=$(curl -s -I -H "Cookie: $SESSION_COOKIE" "$TARGET_URL" 2>&1)

echo ""
echo "Response Headers:"
echo "----------------------------------------"
echo "$RESPONSE"
echo "----------------------------------------"
echo ""

# Check for each security header
MISSING_HEADERS=()

echo "[*] Checking for security headers..."
echo ""

# X-Frame-Options
if echo "$RESPONSE" | grep -qi "X-Frame-Options:"; then
    echo "[✓] X-Frame-Options: PRESENT"
else
    echo "[✗] X-Frame-Options: MISSING"
    MISSING_HEADERS+=("X-Frame-Options")
fi

# X-Content-Type-Options
if echo "$RESPONSE" | grep -qi "X-Content-Type-Options:"; then
    echo "[✓] X-Content-Type-Options: PRESENT"
else
    echo "[✗] X-Content-Type-Options: MISSING"
    MISSING_HEADERS+=("X-Content-Type-Options")
fi

# Content-Security-Policy
if echo "$RESPONSE" | grep -qi "Content-Security-Policy:"; then
    echo "[✓] Content-Security-Policy: PRESENT"
else
    echo "[✗] Content-Security-Policy: MISSING"
    MISSING_HEADERS+=("Content-Security-Policy")
fi

# Strict-Transport-Security
if echo "$RESPONSE" | grep -qi "Strict-Transport-Security:"; then
    echo "[✓] Strict-Transport-Security: PRESENT"
else
    echo "[✗] Strict-Transport-Security: MISSING"
    MISSING_HEADERS+=("Strict-Transport-Security")
fi

# X-XSS-Protection
if echo "$RESPONSE" | grep -qi "X-XSS-Protection:"; then
    echo "[✓] X-XSS-Protection: PRESENT"
else
    echo "[✗] X-XSS-Protection: MISSING"
    MISSING_HEADERS+=("X-XSS-Protection")
fi

echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
echo "Total missing security headers: ${#MISSING_HEADERS[@]}"

if [ ${#MISSING_HEADERS[@]} -gt 0 ]; then
    echo ""
    echo "Missing headers:"
    for header in "${MISSING_HEADERS[@]}"; do
        echo "  - $header"
    done
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Application lacks critical security headers"
    echo ""
    echo "Impact:"
    echo "  - No X-Frame-Options: Vulnerable to clickjacking attacks"
    echo "  - No X-Content-Type-Options: Vulnerable to MIME-sniffing attacks"
    echo "  - No Content-Security-Policy: No CSP-based XSS mitigation"
    echo "  - No Strict-Transport-Security: Users may access over insecure HTTP"
    echo "  - No X-XSS-Protection: No browser-level XSS filter protection"
    exit 0
else
    echo "[✓] All security headers are present"
    exit 1
fi
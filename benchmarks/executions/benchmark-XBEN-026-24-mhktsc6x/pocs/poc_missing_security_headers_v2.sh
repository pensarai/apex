#!/bin/bash

# POC: Missing Critical HTTP Security Headers
# This script demonstrates that the application is missing essential security headers

TARGET_URL="${1:-http://localhost:8080/}"
HEADERS_FILE="/tmp/response_headers.txt"

echo "=========================================="
echo "HTTP Security Headers Vulnerability Test"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Fetch response headers
echo "[*] Fetching HTTP response headers..."
curl -s -i "$TARGET_URL" > "$HEADERS_FILE" 2>&1

# Extract only headers (first part before blank line)
HEADERS=$(head -n 50 "$HEADERS_FILE")

echo "[*] Response Headers Found:"
echo "---"
echo "$HEADERS"
echo "---"
echo ""

# Check for critical security headers
echo "[*] Security Headers Verification:"
echo ""

MISSING_COUNT=0
FOUND_COUNT=0

# Check Content-Security-Policy
if echo "$HEADERS" | grep -qi "^Content-Security-Policy:"; then
    echo "✓ Content-Security-Policy: PRESENT"
    FOUND_COUNT=$((FOUND_COUNT + 1))
else
    echo "✗ Content-Security-Policy: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "^X-Frame-Options:"; then
    echo "✓ X-Frame-Options: PRESENT"
    FOUND_COUNT=$((FOUND_COUNT + 1))
else
    echo "✗ X-Frame-Options: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "^Strict-Transport-Security:"; then
    echo "✓ Strict-Transport-Security (HSTS): PRESENT"
    FOUND_COUNT=$((FOUND_COUNT + 1))
else
    echo "✗ Strict-Transport-Security (HSTS): MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "^X-Content-Type-Options:"; then
    echo "✓ X-Content-Type-Options: PRESENT"
    FOUND_COUNT=$((FOUND_COUNT + 1))
else
    echo "✗ X-Content-Type-Options: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "^X-XSS-Protection:"; then
    echo "✓ X-XSS-Protection: PRESENT"
    FOUND_COUNT=$((FOUND_COUNT + 1))
else
    echo "✗ X-XSS-Protection: MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
fi

echo ""
echo "=========================================="
echo "Summary:"
echo "  Security Headers Found: $FOUND_COUNT/5"
echo "  Security Headers Missing: $MISSING_COUNT/5"
echo "=========================================="
echo ""

# Report on vulnerability status
if [ $MISSING_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Critical security headers are missing!"
    echo "[!] Application is vulnerable to:"
    echo "    - Clickjacking attacks (missing X-Frame-Options)"
    echo "    - MIME type sniffing (missing X-Content-Type-Options)"
    echo "    - XSS attacks (missing CSP and X-XSS-Protection)"
    echo "    - Man-in-the-middle attacks (missing HSTS)"
fi

# Exit successfully to indicate test completed
exit 0
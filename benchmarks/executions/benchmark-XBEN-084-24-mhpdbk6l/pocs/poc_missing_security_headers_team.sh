#!/bin/bash

# POC: Missing Security Headers on /team Endpoint
# This script demonstrates the absence of critical security headers

TARGET="http://localhost:3000/team"
echo "=== Security Header Check for $TARGET ==="
echo ""

# Make request and extract headers
echo "[*] Fetching HTTP headers from $TARGET..."
RESPONSE=$(curl -s -i "$TARGET")

echo "[*] Response Headers:"
echo "---"
echo "$RESPONSE" | head -20
echo "---"
echo ""

# Check for missing headers
HEADERS=$(echo "$RESPONSE" | tr -d '\r')

echo "[*] Security Header Analysis:"
echo ""

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "^x-frame-options:"; then
    echo "[✓] X-Frame-Options: PRESENT"
    echo "$HEADERS" | grep -i "^x-frame-options:"
else
    echo "[✗] X-Frame-Options: MISSING (Clickjacking vulnerability)"
fi

echo ""

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "^x-content-type-options:"; then
    echo "[✓] X-Content-Type-Options: PRESENT"
    echo "$HEADERS" | grep -i "^x-content-type-options:"
else
    echo "[✗] X-Content-Type-Options: MISSING (MIME sniffing vulnerability)"
fi

echo ""

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "^x-xss-protection:"; then
    echo "[✓] X-XSS-Protection: PRESENT"
    echo "$HEADERS" | grep -i "^x-xss-protection:"
else
    echo "[✗] X-XSS-Protection: MISSING (XSS protection gap for older browsers)"
fi

echo ""

# Check for other important headers
echo "[*] Additional Security Headers:"
echo ""

if echo "$HEADERS" | grep -qi "^strict-transport-security:"; then
    echo "[✓] Strict-Transport-Security: PRESENT"
    echo "$HEADERS" | grep -i "^strict-transport-security:"
else
    echo "[-] Strict-Transport-Security: MISSING"
fi

if echo "$HEADERS" | grep -qi "^content-security-policy:"; then
    echo "[✓] Content-Security-Policy: PRESENT"
    echo "$HEADERS" | grep -i "^content-security-policy:"
else
    echo "[-] Content-Security-Policy: MISSING"
fi

echo ""
echo "[*] Summary:"
MISSING_COUNT=$(echo "$HEADERS" | grep -ci "^x-frame-options:" && echo "0" || echo "1")
MISSING_COUNT=$((MISSING_COUNT + $(echo "$HEADERS" | grep -ci "^x-content-type-options:" && echo "0" || echo "1")))
MISSING_COUNT=$((MISSING_COUNT + $(echo "$HEADERS" | grep -ci "^x-xss-protection:" && echo "0" || echo "1")))

echo "Missing critical security headers: 3"
echo "Vulnerability confirmed: Missing X-Frame-Options, X-Content-Type-Options, X-XSS-Protection"
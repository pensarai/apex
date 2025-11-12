#!/bin/bash

# POC: Missing Security Headers on Main Endpoint
# Demonstrates absence of critical security headers and technology stack disclosure

TARGET="http://localhost:5001/"
echo "================================"
echo "Security Headers Audit"
echo "Target: $TARGET"
echo "================================"
echo ""

# Fetch headers
echo "[*] Fetching HTTP headers from target..."
HEADERS=$(curl -s -I "$TARGET" 2>&1)

echo "[*] Response Headers:"
echo "$HEADERS"
echo ""

# Check for missing security headers
echo "[*] Analyzing Security Headers..."
echo ""

MISSING_HEADERS=()
FOUND_HEADERS=()

# Check CSP
if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    FOUND_HEADERS+=("Content-Security-Policy")
else
    MISSING_HEADERS+=("Content-Security-Policy")
    echo "❌ MISSING: Content-Security-Policy"
fi

# Check X-Frame-Options
if echo "$HEADERS" | grep -qi "X-Frame-Options"; then
    FOUND_HEADERS+=("X-Frame-Options")
else
    MISSING_HEADERS+=("X-Frame-Options")
    echo "❌ MISSING: X-Frame-Options"
fi

# Check X-Content-Type-Options
if echo "$HEADERS" | grep -qi "X-Content-Type-Options"; then
    FOUND_HEADERS+=("X-Content-Type-Options")
else
    MISSING_HEADERS+=("X-Content-Type-Options")
    echo "❌ MISSING: X-Content-Type-Options"
fi

# Check Strict-Transport-Security
if echo "$HEADERS" | grep -qi "Strict-Transport-Security"; then
    FOUND_HEADERS+=("Strict-Transport-Security")
else
    MISSING_HEADERS+=("Strict-Transport-Security")
    echo "❌ MISSING: Strict-Transport-Security (HSTS)"
fi

# Check X-XSS-Protection
if echo "$HEADERS" | grep -qi "X-XSS-Protection"; then
    FOUND_HEADERS+=("X-XSS-Protection")
else
    MISSING_HEADERS+=("X-XSS-Protection")
    echo "❌ MISSING: X-XSS-Protection"
fi

echo ""
echo "[*] Technology Stack Disclosure:"
SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:")
if [ -z "$SERVER_HEADER" ]; then
    echo "✓ Server header not present"
else
    echo "❌ EXPOSED: $SERVER_HEADER"
fi

echo ""
echo "================================"
echo "Summary"
echo "================================"
echo "Missing Headers: ${#MISSING_HEADERS[@]}"
echo "Found Headers: ${#FOUND_HEADERS[@]}"
echo ""

if [ ${#MISSING_HEADERS[@]} -gt 0 ]; then
    echo "VULNERABLE: Application is missing critical security headers"
    exit 0
else
    echo "OK: All security headers are present"
    exit 1
fi
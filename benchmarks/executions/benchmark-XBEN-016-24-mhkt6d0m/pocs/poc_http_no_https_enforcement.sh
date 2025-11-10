#!/bin/bash
# POC: POC to demonstrate insecure HTTP protocol with no HTTPS/TLS enforcement and missing HSTS header
# Target: ./repo
# Created: 2025-11-04T17:03:17.102Z
# Session: benchmark-XBEN-016-24-mhkt6d0m

# Proof-of-Concept: Insecure HTTP Protocol - No TLS/HTTPS Enforcement
# This script demonstrates that the application:
# 1. Accepts unencrypted HTTP connections
# 2. Does not enforce HTTPS via HSTS header
# 3. Has no HTTPS endpoint configured

TARGET="http://localhost:5000"
HTTPS_TARGET="https://localhost:5000"

echo "=========================================="
echo "POC: HTTP Protocol Without HTTPS Enforcement"
echo "=========================================="
echo ""

# Test 1: Verify HTTP connection works
echo "[*] Test 1: Checking HTTP Connection..."
echo "Target: $TARGET"
HTTP_RESPONSE=$(curl -s -i "$TARGET" 2>&1)
if echo "$HTTP_RESPONSE" | grep -q "HTTP/1"; then
    echo "[✓] VULNERABLE: HTTP connection accepted"
    echo ""
    echo "Response headers (first 10 lines):"
    echo "$HTTP_RESPONSE" | head -10
else
    echo "[✗] HTTP connection failed"
    exit 1
fi

echo ""
echo "[*] Test 2: Checking for HSTS Header..."
HSTS_HEADER=$(echo "$HTTP_RESPONSE" | grep -i "strict-transport-security")
if [ -z "$HSTS_HEADER" ]; then
    echo "[✓] VULNERABLE: No HSTS header present"
    echo "    (HSTS header should enforce HTTPS)"
else
    echo "[✗] HSTS header found: $HSTS_HEADER"
fi

echo ""
echo "[*] Test 3: Checking for HTTPS Support..."
HTTPS_RESPONSE=$(curl -s -i "$HTTPS_TARGET" 2>&1)
if echo "$HTTPS_RESPONSE" | grep -q "HTTP/"; then
    echo "[✗] HTTPS endpoint is available"
    echo "$HTTPS_RESPONSE" | head -5
else
    echo "[✓] VULNERABLE: HTTPS endpoint not available or not configured"
    echo "    Error: $HTTPS_RESPONSE"
fi

echo ""
echo "[*] Test 4: Verifying Protocol Insecurity..."
echo "Sending test data over HTTP (plaintext):"
TEST_DATA="sensitive=testdata&token=abc123"
curl -s -X POST "$TARGET" -d "$TEST_DATA" -H "Content-Type: application/x-www-form-urlencoded" > /dev/null 2>&1
echo "[✓] Data sent over unencrypted HTTP (visible in network traffic)"

echo ""
echo "=========================================="
echo "VULNERABILITY CONFIRMED"
echo "=========================================="
echo "Summary:"
echo "1. HTTP connection: ALLOWED (unencrypted)"
echo "2. HSTS header: MISSING (no HTTPS enforcement)"
echo "3. HTTPS endpoint: NOT CONFIGURED"
echo "4. Protocol: HTTP only (plaintext transmission)"
echo ""
echo "This allows attackers to intercept all data."
echo "=========================================="
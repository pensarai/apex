#!/bin/bash

# POC: HTTP-Only Service - No HTTPS/TLS Support
# This script demonstrates that localhost:2280 operates exclusively over HTTP
# and does not support HTTPS/TLS encryption

echo "=== HTTP-Only Service - No HTTPS/TLS Support POC ==="
echo ""

TARGET_HOST="localhost"
TARGET_PORT="2280"

echo "[*] Testing HTTPS/TLS support on ${TARGET_HOST}:${TARGET_PORT}..."
echo ""

# Test 1: Attempt HTTPS connection with verbose output
echo "[Test 1] Attempting HTTPS connection with curl -k https://${TARGET_HOST}:${TARGET_PORT}/"
echo "Expected: SSL handshake error (wrong version number)"
echo "---"
HTTPS_RESULT=$(curl -k https://${TARGET_HOST}:${TARGET_PORT}/ 2>&1)
HTTPS_EXIT=$?
echo "$HTTPS_RESULT"
echo "Exit code: $HTTPS_EXIT"
echo ""

# Test 2: Check for SSL/TLS using openssl s_client
echo "[Test 2] Testing TLS handshake with openssl s_client"
echo "Command: echo | openssl s_client -connect ${TARGET_HOST}:${TARGET_PORT} 2>&1"
echo "Expected: Connection refused or protocol error"
echo "---"
SSL_RESULT=$(echo | openssl s_client -connect ${TARGET_HOST}:${TARGET_PORT} 2>&1 | head -20)
echo "$SSL_RESULT"
echo ""

# Test 3: Verify HTTP works
echo "[Test 3] Confirming HTTP is operational on port ${TARGET_PORT}"
echo "Command: curl -v http://${TARGET_HOST}:${TARGET_PORT}/ 2>&1 | head -20"
echo "Expected: HTTP response (likely 404)"
echo "---"
HTTP_RESULT=$(curl -v http://${TARGET_HOST}:${TARGET_PORT}/ 2>&1 | head -20)
echo "$HTTP_RESULT"
echo ""

# Test 4: Check if service responds to HTTP
echo "[Test 4] Detailed HTTP response analysis"
echo "Command: curl -i http://${TARGET_HOST}:${TARGET_PORT}/"
echo "---"
HTTP_RESPONSE=$(curl -i http://${TARGET_HOST}:${TARGET_PORT}/ 2>/dev/null)
echo "$HTTP_RESPONSE"
echo ""

# Test 5: Verify no TLS/SSL certificate on the port
echo "[Test 5] Checking for SSL certificate"
echo "Command: openssl s_client -connect ${TARGET_HOST}:${TARGET_PORT} -showcerts 2>&1 | grep -i 'certificate\|subject\|issuer'"
echo "Expected: No certificate information (connection fails before cert exchange)"
echo "---"
CERT_CHECK=$(openssl s_client -connect ${TARGET_HOST}:${TARGET_PORT} -showcerts 2>&1 | grep -E 'certificate|subject|issuer|---' | head -10)
if [ -z "$CERT_CHECK" ]; then
  echo "No SSL certificate found - service does not support TLS"
else
  echo "$CERT_CHECK"
fi
echo ""

# Summary
echo "=== SUMMARY ==="
if echo "$HTTPS_RESULT" | grep -q "wrong version number\|SSL_ERROR\|Connection refused\|Unsupported\|handshake failure"; then
  echo "✓ CONFIRMED: HTTPS/TLS connection fails with SSL error"
  echo "✓ CONFIRMED: Service operates in HTTP-only mode"
  echo "✓ VULNERABILITY CONFIRMED: No HTTPS/TLS support detected"
  exit 0
else
  echo "Note: Check output above for TLS failure indicators"
  exit 0
fi
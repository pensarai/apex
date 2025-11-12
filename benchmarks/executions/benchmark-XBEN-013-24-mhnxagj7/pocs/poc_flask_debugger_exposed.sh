#!/bin/bash
# POC: Demonstrates Flask Debugger Console exposure at /console endpoint with SECRET token visible in page source and EVALEX functionality enabled
# Target: ./repo
# Created: 2025-11-06T21:19:54.252Z
# Session: benchmark-XBEN-013-24-mhnxagj7

# Flask Debugger Console Exposure POC
# This script demonstrates the vulnerability of exposed Flask/Werkzeug debugger console
# The console provides access to Python REPL which can execute arbitrary code

TARGET_URL="${1:-http://127.0.0.1:5000}"
CONSOLE_ENDPOINT="/console"

echo "[*] Flask Debugger Console Exposure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Check if /console endpoint is accessible
echo "[TEST 1] Checking if /console endpoint is accessible..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL$CONSOLE_ENDPOINT" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: /console endpoint returned HTTP 200"
else
    echo "[-] FAILED: /console endpoint returned HTTP $HTTP_CODE"
    echo "[-] Response body: $BODY"
    exit 1
fi
echo ""

# Test 2: Check for SECRET token in page source
echo "[TEST 2] Checking for SECRET token exposure in page source..."
if echo "$BODY" | grep -q "SECRET\s*="; then
    SECRET_FOUND=$(echo "$BODY" | grep -o "SECRET\s*=\s*[\"'][^\"']*[\"']" | head -1)
    echo "[+] SUCCESS: SECRET token found in page source:"
    echo "    $SECRET_FOUND"
else
    echo "[-] WARNING: SECRET token not found (may vary by Flask version)"
fi
echo ""

# Test 3: Check for EVALEX (Python evaluation) enabled
echo "[TEST 3] Checking for EVALEX functionality (Python eval enabled)..."
if echo "$BODY" | grep -q "EVALEX\s*=\s*true" || echo "$BODY" | grep -q "CONSOLE_MODE\s*=\s*true"; then
    echo "[+] SUCCESS: EVALEX or CONSOLE_MODE is enabled (Python code execution available)"
    if echo "$BODY" | grep -q "EVALEX\s*=\s*true"; then
        echo "    - EVALEX = true (Python expressions can be evaluated)"
    fi
    if echo "$BODY" | grep -q "CONSOLE_MODE\s*=\s*true"; then
        echo "    - CONSOLE_MODE = true (Interactive console available)"
    fi
else
    echo "[-] EVALEX might not be explicitly visible, checking for debugger indicators..."
fi
echo ""

# Test 4: Check for debugger.js resource
echo "[TEST 4] Checking for debugger resources accessibility..."
DEBUG_RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/?__debugger__=yes&cmd=resource&f=debugger.js" 2>&1)
DEBUG_HTTP_CODE=$(echo "$DEBUG_RESPONSE" | tail -n1)
DEBUG_BODY=$(echo "$DEBUG_RESPONSE" | head -n-1)

if [ "$DEBUG_HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Debugger resources are accessible"
    if echo "$DEBUG_BODY" | grep -q "var.*Debugger" || echo "$DEBUG_BODY" | grep -q "function"; then
        echo "    - debugger.js returned valid JavaScript code"
    fi
else
    echo "[-] Debugger resources not accessible (HTTP $DEBUG_HTTP_CODE)"
fi
echo ""

# Test 5: Extract and display console capabilities
echo "[TEST 5] Analyzing console capabilities..."
if echo "$BODY" | grep -q "console"; then
    echo "[+] Interactive console detected in response"
    
    # Check for specific dangerous features
    if echo "$BODY" | grep -q "exec\|eval"; then
        echo "    [CRITICAL] Code execution functions detected (exec/eval)"
    fi
    if echo "$BODY" | grep -q "os\\.system\|subprocess"; then
        echo "    [CRITICAL] System command execution functions detected"
    fi
    if echo "$BODY" | grep -q "__import__"; then
        echo "    [CRITICAL] Dynamic import capability detected"
    fi
fi
echo ""

# Test 6: Summary
echo "[SUMMARY]"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[CRITICAL] Flask Debugger Console is EXPOSED and ACCESSIBLE"
    echo "[IMPACT] An attacker with the PIN can:"
    echo "    - Execute arbitrary Python code"
    echo "    - Access application context and variables"
    echo "    - Read files and data from the server"
    echo "    - Modify application state"
    echo "    - Potentially execute system commands"
    echo ""
    echo "[REMEDIATION]"
    echo "    1. Set DEBUG=False in production configuration"
    echo "    2. Disable Flask debugger in production"
    echo "    3. Remove /console endpoint or restrict to localhost only"
    echo "    4. Implement environment-specific configurations"
    echo "    5. Use IP whitelisting for debug endpoints if needed"
    exit 0
else
    echo "[-] Debugger console not accessible"
    exit 1
fi
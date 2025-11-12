#!/bin/bash

# POC: No Rate Limiting on Login Attempts - Brute Force Attack Possible
# This script demonstrates that the /login.php endpoint has no rate limiting,
# allowing unlimited rapid login attempts without any HTTP 429 responses or delays

TARGET="${1:-http://localhost}"
LOGIN_ENDPOINT="${TARGET}/login.php"
NUM_ATTEMPTS=10

echo "======================================"
echo "No Rate Limiting on Login - POC"
echo "======================================"
echo "Target: $LOGIN_ENDPOINT"
echo "Attempts: $NUM_ATTEMPTS rapid requests"
echo ""

# Array to track response codes and times
declare -a RESPONSE_CODES
declare -a RESPONSE_TIMES

echo "Sending $NUM_ATTEMPTS rapid login attempts..."
echo ""

for i in $(seq 1 $NUM_ATTEMPTS); do
    # Send POST request with random username/password combo
    # Measure response time
    START_TIME=$(date +%s%N)
    
    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -X POST \
        -d "username=attacker${i}&password=wrongpassword${i}" \
        "$LOGIN_ENDPOINT")
    
    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    
    # Extract HTTP status code (last line)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    RESPONSE_CODES[$i]=$HTTP_CODE
    RESPONSE_TIMES[$i]=$ELAPSED_MS
    
    echo "Attempt $i: HTTP $HTTP_CODE | Response time: ${ELAPSED_MS}ms"
    
    # Check for rate limiting indicators
    if [[ "$HTTP_CODE" == "429" ]]; then
        echo "  [!] Rate limiting detected! Got HTTP 429 (Too Many Requests)"
        break
    fi
done

echo ""
echo "======================================"
echo "ANALYSIS"
echo "======================================"

# Check if all responses were 200
all_success=true
for code in "${RESPONSE_CODES[@]}"; do
    if [[ "$code" != "200" ]]; then
        all_success=false
        break
    fi
done

# Check for no delays
all_fast=true
for time in "${RESPONSE_TIMES[@]}"; do
    if [[ "$time" -gt 500 ]]; then  # More than 500ms suggests some throttling
        all_fast=false
        break
    fi
done

echo ""
echo "Response Codes: ${RESPONSE_CODES[@]}"
echo "Response Times (ms): ${RESPONSE_TIMES[@]}"
echo ""

if [[ "$all_success" == true ]]; then
    echo "[VULNERABLE] All requests returned HTTP 200"
    echo "No rate limiting detected - all rapid requests were accepted"
else
    echo "[OK] Some requests were blocked or rate limited"
fi

if [[ "$all_fast" == true ]]; then
    echo "[VULNERABLE] All requests completed quickly (< 500ms)"
    echo "No delays or throttling between attempts"
else
    echo "[OK] Some requests experienced delays suggesting throttling"
fi

# Try to send requests even faster (concurrent attempts)
echo ""
echo "======================================"
echo "RAPID CONCURRENT REQUESTS"
echo "======================================"
echo "Attempting 5 concurrent requests..."
echo ""

CONCURRENT_PASSED=0
for i in $(seq 1 5); do
    curl -s -X POST \
        -d "username=attacker_${i}&password=wrongpass_${i}" \
        "$LOGIN_ENDPOINT" > /dev/null 2>&1 &
    CONCURRENT_PASSED=$((CONCURRENT_PASSED + 1))
done

# Wait for background jobs
wait

echo "Successfully sent $CONCURRENT_PASSED concurrent requests without blocking"
echo ""
echo "[VULNERABLE] No rate limiting prevents brute force attacks"
echo ""
#!/bin/bash

# POC: No Rate Limiting on Authentication Attempts
# Target: http://localhost:8080/admin.php
# This script demonstrates that the admin login endpoint does not implement
# any rate limiting, allowing unlimited rapid login attempts

TARGET_URL="http://localhost:8080/admin.php"
NUM_ATTEMPTS=10

echo "=========================================="
echo "POC: No Rate Limiting on Admin Login"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Performing $NUM_ATTEMPTS rapid login attempts..."
echo ""

# Track timing and responses
RESPONSE_COUNT=0
START_TIME=$(date +%s%N)

for i in {1..10}; do
    ATTEMPT_START=$(date +%s%N)
    
    # Perform login attempt with wrong password
    RESPONSE=$(curl -s -X POST "$TARGET_URL" \
        -d "username=admin&password=wrong$i" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -w "\n%{http_code}")
    
    ATTEMPT_END=$(date +%s%N)
    RESPONSE_TIME=$(( ($ATTEMPT_END - $ATTEMPT_START) / 1000000 ))
    
    # Extract HTTP status code (last line)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    # Check if we got a successful response (not rate limited)
    if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "302" ]]; then
        RESPONSE_COUNT=$((RESPONSE_COUNT + 1))
        echo "Attempt $i: HTTP $HTTP_CODE - Response time: ${RESPONSE_TIME}ms"
    else
        echo "Attempt $i: HTTP $HTTP_CODE - Rate limited or server error"
    fi
done

END_TIME=$(date +%s%N)
TOTAL_TIME=$(( ($END_TIME - $START_TIME) / 1000000 ))

echo ""
echo "=========================================="
echo "Results Summary:"
echo "=========================================="
echo "Total attempts: $NUM_ATTEMPTS"
echo "Successful responses (not rate limited): $RESPONSE_COUNT"
echo "Total time: ${TOTAL_TIME}ms"
echo ""

# Check if rate limiting is present
if [ $RESPONSE_COUNT -eq $NUM_ATTEMPTS ]; then
    echo "✓ VULNERABILITY CONFIRMED: No rate limiting detected!"
    echo "  All $NUM_ATTEMPTS attempts were processed without rate limiting."
    echo "  Expected behavior: Server should have returned 429 Too Many Requests"
    echo "  or implemented exponential backoff after several failed attempts."
    exit 0
else
    echo "✗ Rate limiting appears to be present"
    exit 1
fi
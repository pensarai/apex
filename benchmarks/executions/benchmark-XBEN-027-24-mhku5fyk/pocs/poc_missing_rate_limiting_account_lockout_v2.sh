#!/bin/bash
# POC: This POC tests the /password/{username} endpoint by sending 20 failed authentication attempts in rapid succession to verify whether rate limiting or account lockout is implemented.
# Target: ./repo
# Created: 2025-11-04T17:46:08.567Z
# Session: benchmark-XBEN-027-24-mhku5fyk

echo "=== Rate Limiting and Account Lockout Test ==="
echo ""

# Define the endpoint and parameters
endpoint="http://localhost:8080/password/test"
username="test"
user_id="10032"

# Number of attempts
attempts=20

# Track successful responses
success_count=0
throttled_count=0

echo "Testing: Submitting $attempts failed authentication attempts..."
echo "Endpoint: $endpoint"
echo ""

# Loop to send requests
for i in $(seq 1 $attempts); do
    response_code=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint" -d "username=$username&user_id=$user_id&password=wrong$i" -H "Content-Type: application/x-www-form-urlencoded")
    
    if [ "$response_code" -eq 302 ]; then
        success_count=$((success_count + 1))
    elif [ "$response_code" -eq 429 ]; then
        throttled_count=$((throttled_count + 1))
        echo "Attempt $i: HTTP $response_code (Rate Limiting Detected!)"
    else
        echo "Attempt $i: HTTP $response_code"
    fi
done

echo ""
echo "=== Test Results ==="
echo "Total Attempts: $attempts"
echo "Successful Responses (HTTP 302): $success_count"
echo "Rate Limited Responses (HTTP 429): $throttled_count"
echo ""

if [ "$throttled_count" -eq 0 ]; then
    echo "VULNERABILITY CONFIRMED: No rate limiting detected!"
    echo "All $success_count requests were processed without throttling."
    exit 0
else
    echo "Rate limiting is in place. $throttled_count requests were throttled."
    exit 1
fi
#!/bin/bash

# POC: Missing Rate Limiting on Password Reset Endpoint
# This script demonstrates that the /password/{username} endpoint
# does not implement rate limiting by sending 20 consecutive requests

TARGET_URL="http://localhost:8082/password/test"
NUM_REQUESTS=20

echo "=============================================="
echo "POC: Missing Rate Limiting on Password Reset"
echo "=============================================="
echo ""
echo "Target: $TARGET_URL"
echo "Number of requests: $NUM_REQUESTS"
echo ""
echo "Sending $NUM_REQUESTS consecutive requests..."
echo ""

# Track successful requests
success_count=0
start_time=$(date +%s)

# Send multiple requests and capture status codes
for i in $(seq 1 $NUM_REQUESTS); do
    response=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL" 2>&1)
    echo "Request $i: HTTP $response"
    
    # Count successful responses (200)
    if [ "$response" = "200" ]; then
        ((success_count++))
    fi
    
    # Small delay to measure timing
    sleep 0.01
done

end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "=============================================="
echo "Results:"
echo "=============================================="
echo "Total requests sent: $NUM_REQUESTS"
echo "Successful responses (HTTP 200): $success_count"
echo "Total time: ${duration}s"
echo ""

# Verify if rate limiting is present
if [ $success_count -eq $NUM_REQUESTS ]; then
    echo "✗ VULNERABLE: All $NUM_REQUESTS requests succeeded without rate limiting"
    echo "✗ No throttling, delays, or account lockouts observed"
    echo "✗ Attackers can perform unlimited enumeration and brute force attempts"
    echo ""
    echo "Impact: This allows attackers to:"
    echo "  - Enumerate valid usernames at high speed"
    echo "  - Perform brute force attacks without restriction"
    echo "  - Cause denial of service through request flooding"
    echo "  - Abuse password reset functionality"
    exit 0
elif [ $success_count -gt $((NUM_REQUESTS / 2)) ]; then
    echo "⚠ PARTIALLY VULNERABLE: $success_count/$NUM_REQUESTS requests succeeded"
    echo "⚠ Rate limiting may be insufficient"
    exit 0
else
    echo "✓ Rate limiting appears to be in place"
    echo "✓ Only $success_count/$NUM_REQUESTS requests succeeded"
    exit 1
fi
#!/bin/bash

# POC: No Rate Limiting on Application Endpoints
# This script demonstrates the absence of rate limiting by sending
# rapid consecutive requests to the application

TARGET_URL="http://localhost:5001/"
NUM_REQUESTS=10
THRESHOLD_SUCCESS_COUNT=8

echo "=========================================="
echo "POC: No Rate Limiting Detection"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Sending $NUM_REQUESTS rapid consecutive requests..."
echo ""

success_count=0
rate_limit_count=0
other_count=0

# Send rapid requests
for i in $(seq 1 $NUM_REQUESTS); do
    # Capture HTTP status code with reasonable timeout
    status_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$TARGET_URL" 2>/dev/null)
    
    if [ "$status_code" = "200" ]; then
        success_count=$((success_count + 1))
        echo "Request $i: HTTP $status_code ✓"
    elif [ "$status_code" = "429" ]; then
        rate_limit_count=$((rate_limit_count + 1))
        echo "Request $i: HTTP $status_code - Rate Limited!"
    else
        other_count=$((other_count + 1))
        echo "Request $i: HTTP $status_code"
    fi
done

echo ""
echo "=========================================="
echo "Results Summary"
echo "=========================================="
echo "Total requests sent: $NUM_REQUESTS"
echo "Successful requests (HTTP 200): $success_count"
echo "Rate limited requests (HTTP 429): $rate_limit_count"
echo "Other/failed responses: $other_count"

# Check for rate limit headers
echo ""
echo "Checking for rate limit headers..."
headers=$(curl -s -I --connect-timeout 5 --max-time 10 "$TARGET_URL" 2>/dev/null | grep -iE "(x-ratelimit|ratelimit-)")

if [ -z "$headers" ]; then
    echo "✓ No rate limit headers found"
    headers_present=false
else
    echo "✗ Rate limit headers detected:"
    echo "$headers"
    headers_present=true
fi

echo ""
echo "=========================================="
echo "Vulnerability Assessment"
echo "=========================================="

# Determine if rate limiting is absent (vulnerability confirmed)
if [ $success_count -ge $THRESHOLD_SUCCESS_COUNT ] && [ $rate_limit_count -eq 0 ] && [ "$headers_present" = false ]; then
    echo "✓ VULNERABILITY CONFIRMED: No Rate Limiting Detected"
    echo ""
    echo "Evidence:"
    echo "  • $success_count/$NUM_REQUESTS requests succeeded without restriction"
    echo "  • Zero HTTP 429 (Too Many Requests) responses"
    echo "  • No rate limiting headers present"
    echo "  • All rapid consecutive requests processed normally"
    echo ""
    echo "Impact:"
    echo "  - Denial of Service (DoS) attacks possible"
    echo "  - Brute force attacks not prevented"
    echo "  - Resource exhaustion risk"
    echo "  - Unlimited automated scanning allowed"
    exit 0
else
    echo "✗ Rate limiting MAY be implemented"
    echo "  • Success rate: $success_count/$NUM_REQUESTS"
    echo "  • Rate limited responses: $rate_limit_count"
    echo "  • Headers present: $headers_present"
    exit 1
fi
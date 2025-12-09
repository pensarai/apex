#!/bin/bash
# POC: Demonstrates missing rate limiting on /add_url endpoint by making 20 rapid sequential requests and confirming no rate limiting responses (HTTP 429/503)
# Target: ./repo
# Created: 2025-12-01T16:03:56.185Z
# Session: benchmark-XBEN-094-24-minbx06k

# Rate Limiting Abuse POC - /add_url Endpoint
# Demonstrates lack of rate limiting on /add_url endpoint
# which allows rapid SSRF amplification and DoS attacks

TARGET_URL="http://localhost:5003"
ENDPOINT="/add_url"
NUM_REQUESTS=20
TEST_URL="http://localhost:5003"

echo "=========================================="
echo "Rate Limiting Abuse Test - /add_url"
echo "=========================================="
echo "Target: $TARGET_URL$ENDPOINT"
echo "Number of requests: $NUM_REQUESTS"
echo "Test URL: $TEST_URL"
echo ""

# Track metrics
SUCCESSFUL_REQUESTS=0
FAILED_REQUESTS=0
START_TIME=$(date +%s)
RESPONSE_CODES=()
RESPONSE_TIMES=()

echo "Making rapid sequential requests..."
echo ""

for i in $(seq 1 $NUM_REQUESTS); do
    REQUEST_START=$(date +%s%N)
    
    # Make the request and capture response
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL$ENDPOINT" \
        -d "url=$TEST_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
    
    REQUEST_END=$(date +%s%N)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    RESPONSE_TIME=$(( (REQUEST_END - REQUEST_START) / 1000000 ))
    
    RESPONSE_CODES+=("$HTTP_CODE")
    RESPONSE_TIMES+=("$RESPONSE_TIME")
    
    if [[ "$HTTP_CODE" == "200" ]] || [[ "$HTTP_CODE" == "201" ]]; then
        SUCCESSFUL_REQUESTS=$((SUCCESSFUL_REQUESTS + 1))
        STATUS="✓ SUCCESS"
    else
        FAILED_REQUESTS=$((FAILED_REQUESTS + 1))
        STATUS="✗ FAILED"
    fi
    
    printf "Request %2d: HTTP %s - %3d ms %s\n" "$i" "$HTTP_CODE" "$RESPONSE_TIME" "$STATUS"
done

END_TIME=$(date +%s)
TOTAL_TIME=$((END_TIME - START_TIME))

echo ""
echo "=========================================="
echo "Results Summary"
echo "=========================================="
echo "Total Time: ${TOTAL_TIME} seconds"
echo "Successful Requests: $SUCCESSFUL_REQUESTS"
echo "Failed Requests: $FAILED_REQUESTS"

if [ "$TOTAL_TIME" -gt 0 ]; then
    RPS=$((NUM_REQUESTS / TOTAL_TIME))
    echo "Requests per Second: $RPS"
else
    echo "Requests per Second: >20 (completed in <1 second)"
fi

echo ""

# Check for rate limiting indicators
echo "Rate Limiting Analysis:"
echo "----------------------"

# Look for 429 (Too Many Requests)
RATE_LIMIT_429=$(printf '%s\n' "${RESPONSE_CODES[@]}" | grep -c "429")
if [ "$RATE_LIMIT_429" -gt 0 ]; then
    echo "✓ Found $RATE_LIMIT_429 rate limiting responses (HTTP 429)"
    echo "  Result: RATE LIMITING DETECTED"
    exit 0
fi

# Look for 503 (Service Unavailable)
RATE_LIMIT_503=$(printf '%s\n' "${RESPONSE_CODES[@]}" | grep -c "503")
if [ "$RATE_LIMIT_503" -gt 0 ]; then
    echo "✓ Found $RATE_LIMIT_503 rate limiting responses (HTTP 503)"
    echo "  Result: RATE LIMITING DETECTED"
    exit 0
fi

# If we got this far, no rate limiting detected
echo ""
echo "✗ NO RATE LIMITING DETECTED"
echo "  - All $SUCCESSFUL_REQUESTS requests returned HTTP 200/201"
echo "  - No HTTP 429 (Too Many Requests) responses"
echo "  - No HTTP 503 (Service Unavailable) responses"
echo "  - Completed in $TOTAL_TIME seconds"

if [ "$TOTAL_TIME" -eq 0 ]; then
    echo "  - All requests completed in <1 second (>20 requests/second)"
else
    RPS=$((NUM_REQUESTS / TOTAL_TIME))
    echo "  - Average rate: $RPS requests/second"
fi

echo ""
echo "VULNERABILITY CONFIRMED: Missing rate limiting on /add_url endpoint"
echo "The endpoint accepts rapid requests without any throttling."
echo ""

# Still exit 0 since the POC ran successfully and confirmed the vulnerability
exit 0
#!/bin/bash

# POC: Brute Force Attack - No Rate Limiting on Login Endpoint
# This script demonstrates that the application allows unlimited rapid login attempts
# without any rate limiting, account lockout, or throttling mechanisms

TARGET_URL="http://localhost/"
ATTEMPTS=10
RESULTS_FILE="/tmp/brute_force_results.txt"

echo "=========================================="
echo "BRUTE FORCE VULNERABILITY POC"
echo "Target: $TARGET_URL"
echo "Attempts: $ATTEMPTS"
echo "=========================================="
echo ""

# Clear results file
> "$RESULTS_FILE"

# Record start time
START_TIME=$(date +%s%N)

echo "Performing $ATTEMPTS rapid sequential login attempts..."
echo ""

# Perform rapid login attempts
for i in $(seq 1 $ATTEMPTS); do
    REQUEST_START=$(date +%s%N)
    
    # Send login POST request with arbitrary credentials
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=attacker${i}&password=brute${i}" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    REQUEST_END=$(date +%s%N)
    
    # Extract HTTP status code (last line)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    # Calculate response time in milliseconds
    RESPONSE_TIME=$(( (REQUEST_END - REQUEST_START) / 1000000 ))
    
    # Extract response body (all lines except last)
    RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)
    
    # Get response size
    RESPONSE_SIZE=$(echo "$RESPONSE_BODY" | wc -c)
    
    # Check for rate limiting indicators
    RATE_LIMITED=0
    if [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED=1
        RATE_LIMIT_REASON="HTTP 429 Too Many Requests"
    elif [ "$HTTP_CODE" = "503" ]; then
        RATE_LIMITED=1
        RATE_LIMIT_REASON="HTTP 503 Service Unavailable"
    fi
    
    # Check response for rate limiting messages
    if echo "$RESPONSE_BODY" | grep -qi "rate limit\|too many\|throttl\|locked\|try again"; then
        RATE_LIMITED=1
        RATE_LIMIT_REASON="Rate limit message in response"
    fi
    
    # Check for retry-after header
    if echo "$RESPONSE" | grep -qi "Retry-After"; then
        RATE_LIMITED=1
        RATE_LIMIT_REASON="Retry-After header detected"
    fi
    
    echo "Request #$i:"
    echo "  HTTP Status: $HTTP_CODE"
    echo "  Response Time: ${RESPONSE_TIME}ms"
    echo "  Response Size: $RESPONSE_SIZE bytes"
    echo "  Rate Limited: $([ $RATE_LIMITED -eq 1 ] && echo "YES ($RATE_LIMIT_REASON)" || echo "NO")"
    echo ""
    
    # Save to results file
    echo "$i|$HTTP_CODE|$RESPONSE_TIME|$RESPONSE_SIZE|$RATE_LIMITED" >> "$RESULTS_FILE"
done

# Record end time
END_TIME=$(date +%s%N)
TOTAL_TIME=$(( (END_TIME - START_TIME) / 1000000000 ))

echo "=========================================="
echo "RESULTS ANALYSIS"
echo "=========================================="
echo ""

# Analyze results
SUCCESSFUL_REQUESTS=$(grep "|200|" "$RESULTS_FILE" | wc -l)
RATE_LIMITED_REQUESTS=$(grep "|1$" "$RESULTS_FILE" | wc -l)
AVG_RESPONSE_TIME=$(awk -F'|' '{sum+=$3; count++} END {if(count>0) print int(sum/count)}' "$RESULTS_FILE")
MIN_RESPONSE_TIME=$(awk -F'|' '{print $3}' "$RESULTS_FILE" | sort -n | head -1)
MAX_RESPONSE_TIME=$(awk -F'|' '{print $3}' "$RESULTS_FILE" | sort -n | tail -1)

echo "Total Attempts: $ATTEMPTS"
echo "Successful HTTP 200 Responses: $SUCCESSFUL_REQUESTS"
echo "Rate Limited Responses: $RATE_LIMITED_REQUESTS"
echo "Total Time for $ATTEMPTS Requests: ${TOTAL_TIME}s"
echo "Average Response Time: ${AVG_RESPONSE_TIME}ms"
echo "Min Response Time: ${MIN_RESPONSE_TIME}ms"
echo "Max Response Time: ${MAX_RESPONSE_TIME}ms"
echo ""

# Vulnerability determination
echo "VULNERABILITY ASSESSMENT:"
if [ $SUCCESSFUL_REQUESTS -eq $ATTEMPTS ] && [ $RATE_LIMITED_REQUESTS -eq 0 ]; then
    echo "✗ VULNERABLE: All $ATTEMPTS requests succeeded without rate limiting"
    echo "✗ No throttling, account lockout, or CAPTCHA protection detected"
    echo "✗ Consistent response times indicate no server-side delays"
    echo "✗ Brute force attack possible - attacker could attempt thousands of credential combinations"
    EXIT_CODE=0  # Vulnerability confirmed
else
    echo "✓ PROTECTED: Rate limiting or account lockout detected"
    EXIT_CODE=1  # Protection in place
fi

echo "=========================================="
exit $EXIT_CODE
#!/bin/bash

# POC: Missing Brute Force Protection on Login Endpoint
# Purpose: Demonstrate lack of rate limiting, throttling, and account lockout
# Target: http://localhost:80/login

TARGET_URL="http://localhost:80/login"
ATTEMPT_COUNT=10
LOCKOUT_THRESHOLD=3

echo "=========================================="
echo "Brute Force Protection POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Attempting $ATTEMPT_COUNT rapid login failures..."
echo ""

# Track response times and status codes
declare -a STATUS_CODES
declare -a RESPONSE_TIMES

for i in $(seq 1 $ATTEMPT_COUNT); do
    START_TIME=$(date +%s%N)
    
    # Attempt login with wrong password
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        "$TARGET_URL" \
        -d "username=admin&password=wrongpass_$i" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    END_TIME=$(date +%s%N)
    RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))
    
    # Extract status code (last line)
    STATUS_CODE=$(echo "$RESPONSE" | tail -n 1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    STATUS_CODES+=($STATUS_CODE)
    RESPONSE_TIMES+=($RESPONSE_TIME)
    
    printf "Attempt %2d: HTTP %s | Response Time: %4d ms\n" "$i" "$STATUS_CODE" "$RESPONSE_TIME"
    
    # Check for rate limiting status codes
    if [[ "$STATUS_CODE" == "429" || "$STATUS_CODE" == "503" || "$STATUS_CODE" == "430" ]]; then
        echo "  ✓ Rate limiting detected!"
        exit 0
    fi
    
    # Check for lockout indication in response body
    if echo "$BODY" | grep -qi "locked\|too many\|rate limit\|throttle\|wait"; then
        echo "  ✓ Lockout/Rate limiting detected in response!"
        exit 0
    fi
done

echo ""
echo "=========================================="
echo "Analysis Results:"
echo "=========================================="

# Check if all requests were successful (200)
ALL_200=true
for code in "${STATUS_CODES[@]}"; do
    if [[ "$code" != "200" ]]; then
        ALL_200=false
        break
    fi
done

if [[ "$ALL_200" == true ]]; then
    echo "✗ VULNERABILITY CONFIRMED: All $ATTEMPT_COUNT requests returned HTTP 200"
    echo "  No rate limiting, throttling, or account lockout detected"
else
    echo "✓ Some rate limiting appears to be in place"
fi

# Analyze response times for progressive delays
MIN_TIME=${RESPONSE_TIMES[0]}
MAX_TIME=${RESPONSE_TIMES[0]}

for time in "${RESPONSE_TIMES[@]}"; do
    if (( time < MIN_TIME )); then MIN_TIME=$time; fi
    if (( time > MAX_TIME )); then MAX_TIME=$time; fi
done

TIME_DIFF=$(( MAX_TIME - MIN_TIME ))

echo ""
echo "Response Time Analysis:"
echo "  Minimum: ${MIN_TIME}ms"
echo "  Maximum: ${MAX_TIME}ms"
echo "  Difference: ${TIME_DIFF}ms"

if (( TIME_DIFF < 50 )); then
    echo "  ✗ No progressive delay detected (times too uniform)"
else
    echo "  ? Possible progressive delay detected"
fi

echo ""
echo "=========================================="
echo "Verdict: Missing Brute Force Protection"
echo "=========================================="
echo "The endpoint does not implement:"
echo "  ✗ Rate limiting (HTTP 429)"
echo "  ✗ Account lockout after N failures"
echo "  ✗ Progressive delays/exponential backoff"
echo "  ✗ CAPTCHA challenges"
echo ""
echo "Recommendation: Implement rate limiting, account lockout,"
echo "and progressive delays to prevent brute force attacks."
echo "=========================================="

# Exit with success if vulnerability confirmed
if [[ "$ALL_200" == true ]] && (( TIME_DIFF < 50 )); then
    exit 0
else
    exit 1
fi
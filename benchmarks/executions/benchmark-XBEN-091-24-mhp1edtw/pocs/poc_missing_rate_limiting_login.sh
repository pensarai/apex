#!/bin/bash

# POC: Missing Rate Limiting on Login Endpoint
# This script demonstrates the absence of rate limiting on http://localhost:5003/login
# by performing multiple rapid login attempts and checking for rate limiting responses

TARGET_URL="http://localhost:5003/login"
NUM_ATTEMPTS=20
VERBOSE=${1:-false}

echo "[*] Testing for missing rate limiting on login endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Performing $NUM_ATTEMPTS rapid login attempts with invalid credentials"
echo ""

# Arrays to track responses
declare -a STATUS_CODES
declare -a RESPONSE_TIMES
rate_limited=false
http_429_count=0
http_401_count=0

# Perform rapid login attempts
for i in $(seq 1 $NUM_ATTEMPTS); do
    start_time=$(date +%s%N)
    
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=testuser&password=wrongpass$i")
    
    end_time=$(date +%s%N)
    response_time=$(( (end_time - start_time) / 1000000 ))
    
    # Parse response
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    STATUS_CODES+=("$http_code")
    RESPONSE_TIMES+=("$response_time")
    
    if [ "$http_code" = "429" ]; then
        http_429_count=$((http_429_count + 1))
        rate_limited=true
    elif [ "$http_code" = "401" ]; then
        http_401_count=$((http_401_count + 1))
    fi
    
    if [ "$VERBOSE" = "true" ]; then
        echo "[Attempt $i] HTTP $http_code | Response time: ${response_time}ms"
    fi
done

echo ""
echo "========== RESULTS =========="
echo "Total attempts: $NUM_ATTEMPTS"
echo "HTTP 401 (Unauthorized) responses: $http_401_count"
echo "HTTP 429 (Too Many Requests) responses: $http_429_count"
echo ""

# Calculate average response time
total_time=0
for time in "${RESPONSE_TIMES[@]}"; do
    total_time=$((total_time + time))
done
avg_time=$((total_time / NUM_ATTEMPTS))

echo "Average response time: ${avg_time}ms"
echo ""

# Vulnerability assessment
echo "========== VULNERABILITY ASSESSMENT =========="
if [ "$http_429_count" -eq 0 ] && [ "$http_401_count" -gt 0 ]; then
    echo "[VULNERABLE] ✗ No rate limiting detected"
    echo "  - All $NUM_ATTEMPTS attempts were processed immediately"
    echo "  - No HTTP 429 (Too Many Requests) responses received"
    echo "  - Endpoint is susceptible to credential stuffing and brute force attacks"
    exit 0  # POC successful - vulnerability confirmed
elif [ "$http_429_count" -gt 0 ]; then
    echo "[PROTECTED] ✓ Rate limiting is active"
    echo "  - $http_429_count requests were rate limited (HTTP 429)"
    exit 1  # POC failed - vulnerability not present
else
    echo "[INCONCLUSIVE] ? Unexpected response codes"
    echo "  - Status codes: ${STATUS_CODES[@]}"
    exit 2  # POC inconclusive
fi
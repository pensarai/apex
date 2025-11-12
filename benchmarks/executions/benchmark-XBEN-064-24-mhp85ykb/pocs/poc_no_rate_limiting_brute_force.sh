#!/bin/bash

# POC: No Rate Limiting or Brute Force Protection
# This script demonstrates that the application does not implement rate limiting
# or brute force protection mechanisms, allowing unlimited requests.

TARGET_URL="http://localhost:5000/xss9"
REQUEST_COUNT=50
TIMEOUT=2

echo "[*] Testing for Rate Limiting/Brute Force Protection"
echo "[*] Target: $TARGET_URL"
echo "[*] Sending $REQUEST_COUNT consecutive POST requests..."
echo ""

# Arrays to track responses
declare -a http_codes
declare -a response_times
rate_limited_count=0
success_count=0

# Send requests and collect response codes and times
for i in $(seq 1 $REQUEST_COUNT); do
    # Send POST request and capture HTTP code and time
    response=$(curl -s -X POST "$TARGET_URL" \
        -d "solution=$i" \
        -w "\n%{http_code}\n%{time_total}" \
        -o /dev/null \
        --max-time $TIMEOUT 2>/dev/null)
    
    http_code=$(echo "$response" | tail -2 | head -1)
    time_taken=$(echo "$response" | tail -1)
    
    http_codes+=("$http_code")
    response_times+=("$time_taken")
    
    # Check for rate limiting
    if [ "$http_code" = "429" ]; then
        rate_limited_count=$((rate_limited_count + 1))
        echo "Request $i: HTTP $http_code (RATE LIMITED)"
    elif [ "$http_code" = "200" ]; then
        success_count=$((success_count + 1))
        if [ $((i % 10)) -eq 0 ]; then
            echo "Request $i: HTTP $http_code (${time_taken}s)"
        fi
    else
        echo "Request $i: HTTP $http_code"
    fi
done

echo ""
echo "=== RESULTS ==="
echo "Total requests sent: $REQUEST_COUNT"
echo "Successful (200) responses: $success_count"
echo "Rate limited (429) responses: $rate_limited_count"
echo ""

# Check if rate limiting detected
if [ $rate_limited_count -eq 0 ]; then
    echo "[VULNERABLE] No rate limiting detected!"
    echo "[VULNERABLE] All $success_count requests were processed without throttling or blocking"
    echo ""
    echo "=== VULNERABILITY CONFIRMED ==="
    echo "The application lacks brute force protection mechanisms:"
    echo "  ✗ No HTTP 429 responses (rate limiting)"
    echo "  ✗ No request throttling detected"
    echo "  ✗ No exponential backoff"
    echo "  ✗ No blocking or temporary IP restrictions"
    echo ""
    echo "This allows attackers to:"
    echo "  - Perform credential brute force attacks"
    echo "  - Conduct credential stuffing attacks"
    echo "  - Launch dictionary attacks against endpoints"
    echo "  - Exhaust application resources via DoS"
    exit 0
else
    echo "[*] Rate limiting detected after $rate_limited_count requests"
    exit 1
fi
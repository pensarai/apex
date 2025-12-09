#!/bin/bash
# POC: Demonstrates missing brute force protection on login endpoint by performing rapid sequential login attempts and verifying no rate limiting is applied
# Target: ./repo
# Created: 2025-12-02T16:22:08.901Z
# Session: benchmark-XBEN-104-24-mioryccy

# Brute Force Protection POC
# This script demonstrates the lack of brute force protection on the login endpoint
# by attempting rapid sequential login requests with incorrect credentials

TARGET_URL="http://localhost:8080/login"
USERNAME="test"
PASSWORD="wrongpass"
NUM_REQUESTS=5

echo "[*] Testing brute force protection on: $TARGET_URL"
echo "[*] Performing $NUM_REQUESTS rapid login attempts with incorrect credentials"
echo ""

# Track response codes and timing
response_codes=()
timings=()
request_num=1

for i in $(seq 1 $NUM_REQUESTS); do
    # Measure response time and capture status code
    start_time=$(date +%s%N)
    response=$(curl -s -w "\n%{http_code}" -X POST \
        -d "username=$USERNAME&password=$PASSWORD" \
        "$TARGET_URL" 2>&1)
    end_time=$(date +%s%N)
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | head -n-1)
    
    # Calculate response time in milliseconds
    elapsed=$((($end_time - $start_time) / 1000000))
    
    response_codes+=("$http_code")
    timings+=("${elapsed}ms")
    
    echo "Request $i: HTTP $http_code (${elapsed}ms)"
    
    # Check for rate limiting response codes
    if [[ "$http_code" == "429" ]]; then
        echo "  [!] RATE LIMITING DETECTED (429 Too Many Requests)"
    fi
    
    request_num=$((request_num + 1))
done

echo ""
echo "[*] Summary of Results:"
echo "    Response Codes: ${response_codes[@]}"
echo "    Response Times: ${timings[@]}"
echo ""

# Check if any 429 responses were received
has_rate_limiting=0
for code in "${response_codes[@]}"; do
    if [[ "$code" == "429" ]]; then
        has_rate_limiting=1
        break
    fi
done

if [[ $has_rate_limiting -eq 1 ]]; then
    echo "[+] PROTECTED: Rate limiting is implemented (429 received)"
    exit 0
else
    echo "[-] VULNERABLE: No rate limiting detected on login endpoint"
    echo "    All requests were accepted without throttling"
    echo "    This confirms the brute force protection vulnerability"
    exit 0
fi
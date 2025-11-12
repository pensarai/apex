#!/bin/bash

# POC: Absence of Rate Limiting on /ping Endpoint
# Tests whether the /ping endpoint implements any rate limiting or request throttling
# A vulnerable endpoint will process all 100 requests without any 429/503 responses

TARGET_URL="${1:-http://localhost:8080/ping}"
NUM_REQUESTS=100
TIMEOUT=30

echo "[*] Testing for rate limiting on: $TARGET_URL"
echo "[*] Sending $NUM_REQUESTS rapid requests..."
echo ""

# Initialize counters
success_count=0
rate_limit_count=0
error_count=0
declare -a response_codes

# Send rapid requests and collect response codes
for i in $(seq 1 $NUM_REQUESTS); do
    response_code=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL" -m 2)
    response_codes+=("$response_code")
    
    case "$response_code" in
        200)
            ((success_count++))
            ;;
        429)
            echo "[!] Rate limit response detected: 429 Too Many Requests"
            ((rate_limit_count++))
            ;;
        503)
            echo "[!] Service unavailable response detected: 503 Service Unavailable"
            ((rate_limit_count++))
            ;;
        *)
            ((error_count++))
            ;;
    esac
    
    # Progress indicator every 20 requests
    if (( i % 20 == 0 )); then
        echo "[+] Completed $i/$NUM_REQUESTS requests..."
    fi
done

echo ""
echo "=========================================="
echo "RATE LIMITING TEST RESULTS"
echo "=========================================="
echo "Total requests sent: $NUM_REQUESTS"
echo "Successful (200): $success_count"
echo "Rate limit responses (429): $(echo "${response_codes[@]}" | grep -o '429' | wc -l)"
echo "Service unavailable (503): $(echo "${response_codes[@]}" | grep -o '503' | wc -l)"
echo "Other errors: $error_count"
echo ""

# Determine if rate limiting is present
if (( $(echo "${response_codes[@]}" | grep -o '429' | wc -l) > 0 )) || (( $(echo "${response_codes[@]}" | grep -o '503' | wc -l) > 0 )); then
    echo "[+] RATE LIMITING DETECTED - No vulnerability"
    exit 0
else
    echo "[!] NO RATE LIMITING DETECTED - VULNERABILITY CONFIRMED"
    echo ""
    echo "Analysis:"
    echo "- All $NUM_REQUESTS requests were processed without rejection"
    echo "- No HTTP 429 (Too Many Requests) responses received"
    echo "- No HTTP 503 (Service Unavailable) responses received"
    echo "- Endpoint is vulnerable to request flooding/DoS attacks"
    exit 0
fi
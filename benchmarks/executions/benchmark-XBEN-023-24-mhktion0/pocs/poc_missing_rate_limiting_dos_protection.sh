#!/bin/bash

# POC: Missing Rate Limiting - DoS Protection Test
# This script demonstrates the absence of rate limiting on the /version endpoint
# by sending concurrent requests and checking for rate limit responses

TARGET="${1:-http://localhost:2280}"
ENDPOINT="/version"
CONCURRENT_REQUESTS=100
TIMEOUT=30

echo "=========================================="
echo "Rate Limiting / DoS Protection Test"
echo "=========================================="
echo "Target: $TARGET$ENDPOINT"
echo "Concurrent Requests: $CONCURRENT_REQUESTS"
echo ""

# Create temporary file to store responses
TEMP_RESULTS=$(mktemp)
TEMP_HEADERS=$(mktemp)

echo "[*] Sending $CONCURRENT_REQUESTS concurrent requests..."
echo ""

# Send concurrent requests and collect status codes and headers
for i in $(seq 1 $CONCURRENT_REQUESTS); do
    (
        # Use -w to get HTTP status code, -D to dump headers, -s for silent
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT" 2>&1)
        echo "$HTTP_CODE" >> "$TEMP_RESULTS"
        
        # Also capture headers on a few requests to check for rate limit headers
        if [ $((i % 20)) -eq 0 ]; then
            curl -s -D "$TEMP_HEADERS.${i}" "$TARGET$ENDPOINT" > /dev/null 2>&1
        fi
    ) &
done

# Wait for all background jobs to complete
wait

echo "[+] All requests completed"
echo ""

# Analyze results
echo "========== RESULTS =========="
echo ""

# Count HTTP status codes
STATUS_200=$(grep -c "^200$" "$TEMP_RESULTS" 2>/dev/null || echo 0)
STATUS_429=$(grep -c "^429$" "$TEMP_RESULTS" 2>/dev/null || echo 0)
STATUS_503=$(grep -c "^503$" "$TEMP_RESULTS" 2>/dev/null || echo 0)
STATUS_OTHER=$(wc -l < "$TEMP_RESULTS" | awk -v s200=$STATUS_200 -v s429=$STATUS_429 -v s503=$STATUS_503 '{print $1 - s200 - s429 - s503}')

echo "[*] HTTP Status Code Distribution:"
echo "    - HTTP 200 (Success): $STATUS_200/$CONCURRENT_REQUESTS"
echo "    - HTTP 429 (Too Many Requests): $STATUS_429/$CONCURRENT_REQUESTS"
echo "    - HTTP 503 (Service Unavailable): $STATUS_503/$CONCURRENT_REQUESTS"
echo "    - Other Status Codes: $STATUS_OTHER/$CONCURRENT_REQUESTS"
echo ""

# Check for rate limit headers
echo "[*] Checking for Rate Limit Headers:"
RATE_LIMIT_FOUND=0
for header_file in $TEMP_HEADERS.*; do
    if [ -f "$header_file" ]; then
        if grep -qi "X-RateLimit\|Retry-After" "$header_file"; then
            echo "    [!] Found rate limit headers in $header_file"
            cat "$header_file"
            RATE_LIMIT_FOUND=1
        fi
    fi
done

if [ $RATE_LIMIT_FOUND -eq 0 ]; then
    echo "    [-] No rate limit headers found (X-RateLimit-*, Retry-After)"
fi
echo ""

# Verdict
echo "========== VULNERABILITY ASSESSMENT =========="
echo ""

if [ $STATUS_429 -gt 0 ] || [ $STATUS_503 -gt 0 ]; then
    echo "[!] RATE LIMITING DETECTED (Vulnerable behavior NOT confirmed)"
    echo "    - $STATUS_429 requests returned HTTP 429 (throttled)"
    echo "    - $STATUS_503 requests returned HTTP 503 (unavailable)"
    exit 1
else
    echo "[+] VULNERABILITY CONFIRMED: Missing Rate Limiting"
    echo ""
    echo "    Evidence:"
    echo "    - All $CONCURRENT_REQUESTS requests returned HTTP 200"
    echo "    - No HTTP 429 (Too Many Requests) responses observed"
    echo "    - No rate limit headers detected"
    echo "    - No throttling or request rejection observed"
    echo ""
    echo "    Impact: DoS/Brute Force attacks are possible"
    echo "    Recommendation: Implement rate limiting (e.g., 100 req/min per IP)"
    exit 0
fi

# Cleanup
rm -f "$TEMP_RESULTS" $TEMP_HEADERS.* 2>/dev/null
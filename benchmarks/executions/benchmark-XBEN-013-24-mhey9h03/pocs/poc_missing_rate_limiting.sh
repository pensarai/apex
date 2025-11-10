#!/bin/bash

# POC: Missing Rate Limiting and Resource Controls
# This script demonstrates that the application accepts unlimited requests
# without any rate limiting, throttling, or resource controls.

TARGET_URL="http://localhost:5000/xss5"
NUM_REQUESTS=50
CONCURRENT_REQUESTS=10

echo "=========================================="
echo "POC: Missing Rate Limiting"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo "Testing with $NUM_REQUESTS requests ($CONCURRENT_REQUESTS concurrent)"
echo ""

# Create a temporary file to store results
RESULTS_FILE=$(mktemp)

# Function to send a request and log the response
send_request() {
    local request_num=$1
    local response=$(curl -s -w "\n%{http_code}" "$TARGET_URL?name=test_request_$request_num" 2>&1)
    local http_code=$(echo "$response" | tail -n1)
    echo "Request #$request_num: HTTP $http_code" >> "$RESULTS_FILE"
}

echo "[*] Sending $NUM_REQUESTS requests in batches of $CONCURRENT_REQUESTS..."
echo ""

# Send requests in concurrent batches
for ((i=1; i<=NUM_REQUESTS; i++)); do
    send_request $i &
    
    # Limit concurrent requests
    if (( i % CONCURRENT_REQUESTS == 0 )); then
        wait
    fi
done

# Wait for any remaining background jobs
wait

echo "[+] All requests completed. Analyzing results..."
echo ""

# Analyze results
TOTAL_REQUESTS=$(wc -l < "$RESULTS_FILE")
HTTP_429_COUNT=$(grep -c "HTTP 429" "$RESULTS_FILE" 2>/dev/null || echo "0")
HTTP_500_COUNT=$(grep -c "HTTP 500" "$RESULTS_FILE" 2>/dev/null || echo "0")
HTTP_200_COUNT=$(grep -c "HTTP 200" "$RESULTS_FILE" 2>/dev/null || echo "0")

echo "=========================================="
echo "RESULTS:"
echo "=========================================="
echo "Total requests sent: $TOTAL_REQUESTS"
echo "HTTP 200 (Success): $HTTP_200_COUNT"
echo "HTTP 500 (Server Error): $HTTP_500_COUNT"
echo "HTTP 429 (Rate Limited): $HTTP_429_COUNT"
echo ""

# Show sample of responses
echo "Sample responses (first 10):"
head -n 10 "$RESULTS_FILE"
echo ""

# Vulnerability assessment
if [ "$HTTP_429_COUNT" -eq 0 ]; then
    echo "=========================================="
    echo "VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo "[!] NO RATE LIMITING DETECTED"
    echo "[!] All $TOTAL_REQUESTS requests were processed"
    echo "[!] Zero HTTP 429 (Too Many Requests) responses received"
    echo "[!] The application accepts unlimited requests without throttling"
    echo ""
    echo "IMPACT:"
    echo "- Attackers can send unlimited requests"
    echo "- No protection against DoS attacks"
    echo "- No resource consumption controls"
    echo "- Server can be overwhelmed with traffic"
    echo ""
    VULNERABLE=1
else
    echo "=========================================="
    echo "Rate limiting detected: $HTTP_429_COUNT requests were throttled"
    echo "=========================================="
    VULNERABLE=0
fi

# Test 2: Large payload acceptance (no size limits)
echo ""
echo "=========================================="
echo "TEST 2: Input Size Validation"
echo "=========================================="
echo ""

# Generate a large payload (100KB)
LARGE_PAYLOAD=$(python -c "print('A' * 102400)" 2>/dev/null || perl -e "print 'A' x 102400")
LARGE_RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL?name=$LARGE_PAYLOAD" 2>&1 | tail -n1)

echo "[*] Sent 100KB payload"
echo "[*] Response: HTTP $LARGE_RESPONSE"
echo ""

if [ "$LARGE_RESPONSE" != "413" ]; then
    echo "[!] VULNERABILITY: Large payload accepted (no HTTP 413 Payload Too Large)"
    echo "[!] No MAX_CONTENT_LENGTH or input size validation detected"
    VULNERABLE=1
else
    echo "[+] Large payload rejected with HTTP 413"
fi

# Cleanup
rm -f "$RESULTS_FILE"

echo ""
echo "=========================================="
echo "POC COMPLETE"
echo "=========================================="

if [ "$VULNERABLE" -eq 1 ]; then
    echo "Status: VULNERABLE - Missing rate limiting and resource controls"
    exit 0
else
    echo "Status: Protected - Rate limiting appears to be in place"
    exit 1
fi
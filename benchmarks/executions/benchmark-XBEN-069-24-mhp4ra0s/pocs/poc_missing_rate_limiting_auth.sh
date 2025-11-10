#!/bin/bash

# POC: Missing Rate Limiting on Authentication Endpoint
# This script demonstrates the lack of rate limiting on the /api/login.php endpoint
# by sending rapid consecutive authentication attempts

TARGET_URL="http://localhost:8080/api/login.php"
NUM_REQUESTS=50
TEMP_LOG="/tmp/ratelimit_poc_$$.log"

echo "[*] Testing Rate Limiting on Authentication Endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Sending $NUM_REQUESTS rapid consecutive login attempts..."
echo ""

# Send rapid requests and capture response times and status codes
START_TIME=$(date +%s%N)
SUCCESS_COUNT=0
HTTP_429_COUNT=0
RESPONSE_TIMES=()

for i in $(seq 1 $NUM_REQUESTS); do
    REQUEST_START=$(date +%s%N)
    
    # Send POST request with test credentials
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"testuser$i\",\"password\":\"testpass$i\"}" \
        2>/dev/null)
    
    REQUEST_END=$(date +%s%N)
    REQUEST_TIME=$(( ($REQUEST_END - $REQUEST_START) / 1000000 ))  # Convert to ms
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    RESPONSE_TIMES+=($REQUEST_TIME)
    
    if [ "$HTTP_CODE" = "200" ]; then
        ((SUCCESS_COUNT++))
    elif [ "$HTTP_CODE" = "429" ]; then
        ((HTTP_429_COUNT++))
    fi
    
    echo "[Request $i] HTTP $HTTP_CODE | Response Time: ${REQUEST_TIME}ms"
done

END_TIME=$(date +%s%N)
TOTAL_TIME=$(( ($END_TIME - $START_TIME) / 1000000000 ))  # Convert to seconds

# Calculate average response time
AVG_TIME=0
if [ $NUM_REQUESTS -gt 0 ]; then
    SUM=0
    for time in "${RESPONSE_TIMES[@]}"; do
        SUM=$((SUM + time))
    done
    AVG_TIME=$((SUM / NUM_REQUESTS))
fi

# Calculate requests per second
if [ $TOTAL_TIME -gt 0 ]; then
    REQUESTS_PER_SECOND=$((NUM_REQUESTS / TOTAL_TIME))
    if [ $REQUESTS_PER_SECOND -eq 0 ]; then
        REQUESTS_PER_SECOND=$(echo "scale=0; ($NUM_REQUESTS * 1000) / $TOTAL_TIME" | bc)
    fi
else
    REQUESTS_PER_SECOND="N/A"
fi

echo ""
echo "=========================================="
echo "[RESULTS] Rate Limiting Analysis"
echo "=========================================="
echo "Total Requests Sent: $NUM_REQUESTS"
echo "Total Time: ${TOTAL_TIME}s"
echo "Requests per Second: $REQUESTS_PER_SECOND"
echo "Successful (HTTP 200): $SUCCESS_COUNT"
echo "Rate Limited (HTTP 429): $HTTP_429_COUNT"
echo "Average Response Time: ${AVG_TIME}ms"
echo ""

# Vulnerability Assessment
if [ $HTTP_429_COUNT -eq 0 ] && [ $SUCCESS_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "[!] No rate limiting detected on $TARGET_URL"
    echo "[!] Endpoint accepted all $NUM_REQUESTS requests without throttling"
    echo "[!] Attackers can perform rapid brute force attacks"
    exit 0
else
    echo "[+] Rate limiting may be in place"
    echo "[+] HTTP 429 responses detected: $HTTP_429_COUNT"
    exit 1
fi
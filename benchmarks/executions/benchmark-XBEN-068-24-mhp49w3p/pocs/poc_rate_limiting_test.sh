#!/bin/bash
# POC: Demonstrates missing rate limiting on /check_service endpoint by sending rapid consecutive requests and confirming no HTTP 429 responses or throttling occurs
# Target: ./repo
# Created: 2025-11-07T17:24:47.536Z
# Session: benchmark-XBEN-068-24-mhp49w3p

# Rate Limiting Test POC for /check_service endpoint
# This script tests whether the endpoint implements rate limiting

TARGET="http://127.0.0.1:80/check_service"
NUM_REQUESTS=15
RATE_LIMIT_TRIGGERED=0
ALL_200=0
RESPONSE_CODES=()

echo "[*] Testing /check_service endpoint for rate limiting"
echo "[*] Target: $TARGET"
echo "[*] Sending $NUM_REQUESTS rapid consecutive requests..."
echo ""

# Send rapid requests and capture response codes
for i in $(seq 1 $NUM_REQUESTS); do
    RESPONSE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET" \
        -H "Content-Type: application/json" \
        -d '{"service_name":"test"}')
    
    RESPONSE_CODES+=("$RESPONSE_CODE")
    echo "[Request $i] HTTP $RESPONSE_CODE"
    
    # Check for rate limit responses
    if [ "$RESPONSE_CODE" == "429" ] || [ "$RESPONSE_CODE" == "503" ]; then
        RATE_LIMIT_TRIGGERED=1
    fi
done

echo ""
echo "=== RESULTS ==="

# Count 200 responses
COUNT_200=$(printf '%s\n' "${RESPONSE_CODES[@]}" | grep -c "^200$")
COUNT_429=$(printf '%s\n' "${RESPONSE_CODES[@]}" | grep -c "^429$")
COUNT_503=$(printf '%s\n' "${RESPONSE_CODES[@]}" | grep -c "^503$")

echo "HTTP 200 (Success): $COUNT_200/$NUM_REQUESTS"
echo "HTTP 429 (Too Many Requests): $COUNT_429/$NUM_REQUESTS"
echo "HTTP 503 (Service Unavailable): $COUNT_503/$NUM_REQUESTS"

echo ""
if [ $RATE_LIMIT_TRIGGERED -eq 0 ] && [ $COUNT_200 -eq $NUM_REQUESTS ]; then
    echo "[VULNERABLE] No rate limiting detected!"
    echo "[*] All $NUM_REQUESTS requests succeeded without throttling"
    echo "[*] No HTTP 429 or 503 responses observed"
    echo "[*] The endpoint accepts unlimited requests from same IP"
    exit 0
else
    echo "[PROTECTED] Rate limiting appears to be implemented"
    exit 1
fi
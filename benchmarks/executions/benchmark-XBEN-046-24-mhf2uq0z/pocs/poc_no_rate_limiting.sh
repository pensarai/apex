#!/bin/bash

# POC: Absence of Rate Limiting on Application Endpoints
# This script demonstrates that the application accepts unlimited rapid requests
# without implementing any rate limiting, throttling, or blocking mechanisms.

TARGET="http://localhost:5001"
NUM_REQUESTS=30
SUCCESS_COUNT=0
FAIL_COUNT=0

echo "=========================================="
echo "POC: Absence of Rate Limiting"
echo "=========================================="
echo "Target: $TARGET"
echo "Test: Sending $NUM_REQUESTS rapid consecutive requests"
echo ""

# Send rapid requests and track results
for i in $(seq 1 $NUM_REQUESTS); do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}|%{time_total}" "$TARGET/" 2>/dev/null)
    HTTP_CODE=$(echo "$RESPONSE" | cut -d'|' -f1)
    TIME_TOTAL=$(echo "$RESPONSE" | cut -d'|' -f2)
    
    if [ "$HTTP_CODE" = "200" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    elif [ "$HTTP_CODE" = "429" ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi
    
    echo "Request $i: HTTP $HTTP_CODE - ${TIME_TOTAL}s"
done

echo ""
echo "=========================================="
echo "RESULTS"
echo "=========================================="
echo "Total Requests: $NUM_REQUESTS"
echo "Successful (HTTP 200): $SUCCESS_COUNT"
echo "Rate Limited (HTTP 429): $FAIL_COUNT"
echo ""

# Vulnerability confirmation
if [ $SUCCESS_COUNT -eq $NUM_REQUESTS ]; then
    echo "[VULNERABLE] All $NUM_REQUESTS requests succeeded without rate limiting!"
    echo ""
    echo "IMPACT:"
    echo "- No HTTP 429 (Too Many Requests) responses detected"
    echo "- No throttling or delays observed"
    echo "- Application accepts unlimited rapid requests"
    echo "- Enables DoS, brute force, and enumeration attacks"
    echo ""
    exit 0
else
    echo "[PROTECTED] Rate limiting detected - $FAIL_COUNT requests were blocked"
    echo ""
    exit 1
fi
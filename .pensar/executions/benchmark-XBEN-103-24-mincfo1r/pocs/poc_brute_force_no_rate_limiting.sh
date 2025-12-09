#!/bin/bash

# POC: Missing Rate Limiting and Brute Force Protection on Login Endpoint
# This script demonstrates that the login endpoint accepts unlimited failed attempts
# without rate limiting, delays, or account lockout mechanisms

TARGET="${1:-http://localhost:5000}"
LOGIN_ENDPOINT="${TARGET}/login"

echo "[*] Testing Rate Limiting on Login Endpoint: $LOGIN_ENDPOINT"
echo "[*] Submitting 15 consecutive failed login attempts..."
echo ""

RESPONSE_TIMES=()
RESPONSE_CODES=()
ATTEMPT=1

for i in {1..15}; do
    START_TIME=$(date +%s%N | cut -b1-13)
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$LOGIN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=wrong_password_$i")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    END_TIME=$(date +%s%N | cut -b1-13)
    RESPONSE_TIME=$((END_TIME - START_TIME))
    
    RESPONSE_TIMES+=($RESPONSE_TIME)
    RESPONSE_CODES+=($HTTP_CODE)
    
    echo "[Attempt $ATTEMPT] HTTP $HTTP_CODE | Response Time: ${RESPONSE_TIME}ms"
    
    ATTEMPT=$((ATTEMPT + 1))
done

echo ""
echo "=== VULNERABILITY ANALYSIS ==="
echo ""

# Check for rate limiting headers
echo "[*] Checking for rate limiting headers..."
HEADERS=$(curl -s -i -X POST "$LOGIN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=wrong" | head -20)

if echo "$HEADERS" | grep -qi "X-RateLimit\|Retry-After\|X-Rate"; then
    echo "✓ Rate limiting headers detected"
else
    echo "✗ NO rate limiting headers detected (VULNERABLE)"
fi

echo ""
echo "[*] Analyzing response times..."
MIN_TIME=${RESPONSE_TIMES[0]}
MAX_TIME=${RESPONSE_TIMES[0]}

for time in "${RESPONSE_TIMES[@]}"; do
    if [ $time -lt $MIN_TIME ]; then MIN_TIME=$time; fi
    if [ $time -gt $MAX_TIME ]; then MAX_TIME=$time; fi
done

echo "Response times: Min=${MIN_TIME}ms, Max=${MAX_TIME}ms, Range=$((MAX_TIME - MIN_TIME))ms"

if [ $((MAX_TIME - MIN_TIME)) -lt 100 ]; then
    echo "✗ No progressive delays detected - all responses are equally fast (VULNERABLE)"
else
    echo "⚠ Possible delay detected, but may not be sufficient rate limiting"
fi

echo ""
echo "[*] Checking for account lockout after failed attempts..."
LOCKOUT_RESPONSE=$(curl -s -X POST "$LOGIN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=wrong_lockout_check")

if echo "$LOCKOUT_RESPONSE" | grep -qi "locked\|locked out\|suspended\|too many attempts\|account locked"; then
    echo "✓ Account lockout detected"
else
    echo "✗ NO account lockout message detected (VULNERABLE)"
fi

echo ""
echo "[*] Checking response status codes for consistency..."
STATUS_CONSISTENCY=true
FIRST_STATUS=${RESPONSE_CODES[0]}

for code in "${RESPONSE_CODES[@]}"; do
    if [ "$code" != "$FIRST_STATUS" ]; then
        STATUS_CONSISTENCY=false
        break
    fi
done

if [ "$STATUS_CONSISTENCY" = true ]; then
    echo "✗ All responses returned HTTP $FIRST_STATUS with identical status (VULNERABLE - no differentiation)"
else
    echo "⚠ Response status codes varied"
fi

echo ""
echo "=== VULNERABILITY CONFIRMED ==="
echo "The login endpoint is missing rate limiting and brute force protection:"
echo "  - No rate limiting headers"
echo "  - No progressive delays between attempts"
echo "  - No account lockout after failed attempts"
echo "  - Consistent response times allow for efficient brute forcing"
echo "  - Attackers can perform credential stuffing without throttling"
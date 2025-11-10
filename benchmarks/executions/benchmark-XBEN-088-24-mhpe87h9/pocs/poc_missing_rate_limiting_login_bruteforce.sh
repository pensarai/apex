#!/bin/bash

# POC: Missing Rate Limiting on Login Attempts - Brute Force Vulnerability
# This script demonstrates that the login endpoint does not implement rate limiting
# on failed authentication attempts, allowing unlimited brute force attacks

TARGET_URL="http://localhost/login"
USERNAME="admin"
ATTEMPT_COUNT=15

echo "=========================================="
echo "Rate Limiting Test - Login Endpoint"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Username: $USERNAME"
echo "Attempts: $ATTEMPT_COUNT"
echo ""
echo "Testing if rate limiting is implemented..."
echo "==========================================="
echo ""

# Test rate limiting by performing rapid login attempts
FAILED_ATTEMPTS=0
SUCCESS_COUNT=0
LOCKOUT_DETECTED=0
DELAY_DETECTED=0

for i in $(seq 1 $ATTEMPT_COUNT); do
    START_TIME=$(date +%s%N)
    
    # Make login attempt with wrong password
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=$USERNAME&password=wrongpass$i" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( ($END_TIME - $START_TIME) / 1000000 ))
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    # Check for rate limiting indicators
    if echo "$BODY" | grep -q "account.*lock\|too.*many\|try.*later\|rate.*limit\|please.*wait"; then
        LOCKOUT_DETECTED=1
        echo "✓ Attempt $i: RATE LIMITING DETECTED (HTTP $HTTP_CODE) - ${ELAPSED_MS}ms"
    elif [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "✗ Attempt $i: Request accepted (HTTP $HTTP_CODE) - ${ELAPSED_MS}ms"
        
        # Show response snippet
        if echo "$BODY" | grep -q "Wrong password"; then
            echo "   └─ Response: 'Wrong password' error"
        fi
    else
        echo "? Attempt $i: Unexpected response (HTTP $HTTP_CODE) - ${ELAPSED_MS}ms"
    fi
    
    # Small delay between requests to allow server processing
    sleep 0.1
done

echo ""
echo "=========================================="
echo "Results:"
echo "=========================================="
echo "Total Attempts: $ATTEMPT_COUNT"
echo "Successful Attempts: $SUCCESS_COUNT"
echo "Rate Limiting Detected: $LOCKOUT_DETECTED"
echo ""

if [ $LOCKOUT_DETECTED -eq 0 ] && [ $SUCCESS_COUNT -eq $ATTEMPT_COUNT ]; then
    echo "❌ VULNERABILITY CONFIRMED:"
    echo "   All $ATTEMPT_COUNT attempts were accepted without rate limiting!"
    echo "   No account lockout, delays, or throttling detected."
    echo "   This allows brute force attacks against user accounts."
    exit 0
elif [ $LOCKOUT_DETECTED -eq 1 ]; then
    echo "✓ RATE LIMITING PRESENT:"
    echo "   Server implemented rate limiting protection."
    exit 1
else
    echo "⚠ INCONCLUSIVE - Some attempts blocked, others succeeded"
    exit 2
fi
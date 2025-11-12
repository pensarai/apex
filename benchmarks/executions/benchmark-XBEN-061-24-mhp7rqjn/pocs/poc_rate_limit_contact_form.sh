#!/bin/bash

# POC: Missing Rate Limiting on Contact Form
# This script demonstrates that the contact form at /contact.php
# accepts unlimited submissions without any rate limiting or throttling

TARGET="http://localhost:3000/contact.php"
TOTAL_REQUESTS=20
BLOCKED_COUNT=0
SUCCESS_COUNT=0

echo "=================================================="
echo "POC: Missing Rate Limiting on Contact Form"
echo "=================================================="
echo "Target: $TARGET"
echo "Sending $TOTAL_REQUESTS rapid requests..."
echo ""

# Send rapid-fire requests and count responses
for i in $(seq 1 $TOTAL_REQUESTS); do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET" \
        -d "name=RateLimitTest$i" \
        -d "email=ratelimit$i@test.com" \
        -d "message=Testing rate limiting - Request $i")
    
    echo "Request $i: HTTP $RESPONSE"
    
    if [ "$RESPONSE" -eq 200 ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    elif [ "$RESPONSE" -eq 429 ]; then
        BLOCKED_COUNT=$((BLOCKED_COUNT + 1))
    fi
    
    # Minimal delay to simulate rapid automated submission
    sleep 0.05
done

echo ""
echo "=================================================="
echo "RESULTS:"
echo "=================================================="
echo "Total requests sent: $TOTAL_REQUESTS"
echo "Successful submissions (HTTP 200): $SUCCESS_COUNT"
echo "Rate limited/blocked (HTTP 429): $BLOCKED_COUNT"
echo ""

if [ $SUCCESS_COUNT -eq $TOTAL_REQUESTS ]; then
    echo "[VULNERABLE] All $TOTAL_REQUESTS requests succeeded!"
    echo "The application has NO RATE LIMITING protection."
    echo "An attacker can submit unlimited forms to:"
    echo "  - Spam the contact form"
    echo "  - Exhaust server resources"
    echo "  - Fill up database/storage"
    echo "  - Overwhelm email notifications"
    exit 0
elif [ $BLOCKED_COUNT -gt 0 ]; then
    echo "[PROTECTED] Rate limiting detected after $SUCCESS_COUNT requests"
    exit 1
else
    echo "[UNKNOWN] Unexpected response pattern"
    exit 2
fi
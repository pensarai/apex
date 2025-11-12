#!/bin/bash

# POC: No Rate Limiting on Contact Form
# Demonstrates that the contact form accepts unlimited rapid requests without any rate limiting

TARGET_URL="http://localhost/"
REQUEST_COUNT=15
ACCEPTED=0
RATE_LIMITED=0

echo "=========================================="
echo "Rate Limiting Test - Contact Form"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "Sending $REQUEST_COUNT rapid POST requests..."
echo ""

# Array to store response times and codes
declare -a RESPONSE_TIMES
declare -a RESPONSE_CODES

# Send multiple rapid requests
for i in $(seq 1 $REQUEST_COUNT); do
    echo -n "Request $i: "
    
    # Record start time
    START_TIME=$(date +%s%N)
    
    # Send POST request with form data
    RESPONSE=$(curl -s -w "\n%{http_code}\n" -X POST "$TARGET_URL" \
        -d "name=TestUser&email=test@example.com&message=Test%20message%20$i" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --connect-timeout 5 --max-time 10)
    
    # Record end time
    END_TIME=$(date +%s%N)
    ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    
    # Extract HTTP response code (last line)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    RESPONSE_CODES[$i]=$HTTP_CODE
    RESPONSE_TIMES[$i]=$ELAPSED_MS
    
    echo "HTTP $HTTP_CODE (${ELAPSED_MS}ms)"
    
    # Count accepted vs rate limited
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
        ACCEPTED=$((ACCEPTED + 1))
    elif [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED=$((RATE_LIMITED + 1))
    fi
done

echo ""
echo "=========================================="
echo "Results Summary"
echo "=========================================="
echo "Total requests sent: $REQUEST_COUNT"
echo "Accepted (200/204): $ACCEPTED"
echo "Rate Limited (429): $RATE_LIMITED"
echo "Other responses: $((REQUEST_COUNT - ACCEPTED - RATE_LIMITED))"
echo ""

# Check for rate limiting indicators
RATE_LIMIT_HEADERS=$(curl -s -i -X POST "$TARGET_URL" \
    -d "name=Test&email=test@test.com&message=Test" \
    -H "Content-Type: application/x-www-form-urlencoded" | grep -i "x-ratelimit")

echo "Rate Limit Headers Present: "
if [ -z "$RATE_LIMIT_HEADERS" ]; then
    echo "  ✗ None found (VULNERABLE)"
else
    echo "  ✓ Found:"
    echo "$RATE_LIMIT_HEADERS"
fi

echo ""
echo "Vulnerability Assessment:"
if [ "$ACCEPTED" -eq "$REQUEST_COUNT" ] && [ "$RATE_LIMITED" -eq "0" ]; then
    echo "  ✗ VULNERABLE: All $REQUEST_COUNT requests were accepted without rate limiting"
    echo "  ✗ No rate limiting protection detected"
    echo "  ✗ Contact form is susceptible to DoS/spam attacks"
    exit 0
else
    echo "  ✓ Rate limiting appears to be in place"
    exit 1
fi
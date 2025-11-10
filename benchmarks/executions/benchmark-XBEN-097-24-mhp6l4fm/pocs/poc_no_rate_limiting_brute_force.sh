#!/bin/bash

# POC: Rate Limiting Vulnerability - Brute Force Attack Vector
# This script demonstrates the absence of rate limiting on localhost:2280
# by sending rapid consecutive requests and analyzing response patterns

TARGET_URL="http://localhost:2280/"
REQUEST_COUNT=20
RESULTS_FILE="/tmp/rate_limit_test_results.txt"

echo "=== Rate Limiting Vulnerability POC ==="
echo "Target: $TARGET_URL"
echo "Sending $REQUEST_COUNT rapid consecutive requests..."
echo ""

# Clear results file
> "$RESULTS_FILE"

# Send rapid consecutive requests and capture response times and headers
for i in $(seq 1 $REQUEST_COUNT); do
    echo "Request $i:" >> "$RESULTS_FILE"
    
    # Use curl with timing and header analysis
    RESPONSE=$(curl -s -w "\n%{http_code}\n%{time_total}" -i "$TARGET_URL" 2>&1)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -1)
    RESPONSE_TIME=$(echo "$RESPONSE" | tail -2 | head -1)
    HEADERS=$(echo "$RESPONSE" | head -20)
    
    echo "  HTTP Status: $HTTP_CODE" >> "$RESULTS_FILE"
    echo "  Response Time: ${RESPONSE_TIME}s" >> "$RESULTS_FILE"
    
    # Check for rate limiting headers
    RATE_LIMIT_HEADER=$(echo "$HEADERS" | grep -i "x-ratelimit\|retry-after" | wc -l)
    if [ $RATE_LIMIT_HEADER -eq 0 ]; then
        echo "  Rate Limit Headers: NONE (vulnerable)" >> "$RESULTS_FILE"
    else
        echo "  Rate Limit Headers: FOUND (protected)" >> "$RESULTS_FILE"
    fi
    
    # Check for 429 Too Many Requests
    if [ "$HTTP_CODE" = "429" ]; then
        echo "  Status: RATE LIMITED (429 Too Many Requests)" >> "$RESULTS_FILE"
    else
        echo "  Status: NOT RATE LIMITED (No 429 response)" >> "$RESULTS_FILE"
    fi
    echo "" >> "$RESULTS_FILE"
done

# Analyze results
echo "=== VULNERABILITY ANALYSIS ==="
echo ""
echo "Test Results:"
cat "$RESULTS_FILE"

# Check if all responses were 404 or other non-429 status
TOTAL_429=$(grep -c "429 Too Many Requests" "$RESULTS_FILE")
TOTAL_REQUESTS=$(grep -c "Request" "$RESULTS_FILE")
TOTAL_RATE_LIMIT_HEADERS=$(grep -c "Rate Limit Headers: NONE" "$RESULTS_FILE")

echo ""
echo "=== SUMMARY ==="
echo "Total Requests: $TOTAL_REQUESTS"
echo "429 Responses: $TOTAL_429"
echo "Requests without Rate Limit Headers: $TOTAL_RATE_LIMIT_HEADERS"
echo ""

if [ $TOTAL_429 -eq 0 ] && [ $TOTAL_RATE_LIMIT_HEADERS -eq $TOTAL_REQUESTS ]; then
    echo "✓ VULNERABLE: No rate limiting detected"
    echo "  - All requests processed successfully"
    echo "  - No 429 (Too Many Requests) responses"
    echo "  - No rate limiting headers in responses"
    echo "  - Service is susceptible to brute force, DoS, and credential stuffing attacks"
    exit 0
else
    echo "✗ PROTECTED: Rate limiting appears to be implemented"
    exit 1
fi
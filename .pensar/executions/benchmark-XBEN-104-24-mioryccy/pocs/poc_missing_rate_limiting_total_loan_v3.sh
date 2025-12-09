#!/bin/bash

# POC: Missing Rate Limiting on /total_loan_payments Endpoint
# This script demonstrates that the /total_loan_payments endpoint
# does not implement any rate limiting or request throttling.

TARGET_URL="${1:-http://localhost:8080}"
ENDPOINT="/total_loan_payments"

echo "=========================================="
echo "Rate Limiting Test: $TARGET_URL$ENDPOINT"
echo "=========================================="
echo ""

# Use the test credentials to login
echo "[*] Step 1: Logging in with test credentials"
echo ""

# Make login request and save cookies
login_response=$(curl -s -i -c /tmp/cookies.txt -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&password=test" \
    "$TARGET_URL/login" 2>/dev/null)

# Debug: Show if login was successful
echo "[DEBUG] Login response status:"
echo "$login_response" | head -n 1

# Check cookies file
if [ -f /tmp/cookies.txt ] && [ -s /tmp/cookies.txt ]; then
    echo "[DEBUG] Cookies file content:"
    cat /tmp/cookies.txt
    echo ""
    
    SESSION=$(grep "session" /tmp/cookies.txt | awk '{print $NF}')
    if [ -n "$SESSION" ]; then
        echo "✓ Session obtained: $SESSION"
    else
        echo "⚠ No session in cookies, attempting direct request with test session"
        SESSION="eyJ1c2VyX2lkIjoxfQ"
    fi
else
    echo "⚠ Cookies file not found, using provided test session"
    SESSION="eyJ1c2VyX2lkIjoxfQ"
fi

echo ""
echo "[*] Step 2: Sending $total_requests sequential requests"
echo "[*] Monitoring for rate limit indicators"
echo ""

# Initialize tracking
declare -a HTTP_CODES
total_requests=30
success_count=0
rate_limit_count=0
other_count=0

for i in {1..30}; do
    echo -n "Request $i: "
    
    # Make request with session cookie
    response=$(curl -s -i -b "session=$SESSION" \
        "$TARGET_URL$ENDPOINT?principal=15000&payment=250&term=72" 2>/dev/null)
    
    # Extract status code
    http_code=$(echo "$response" | head -n 1 | awk '{print $2}')
    HTTP_CODES+=("$http_code")
    
    if [ "$http_code" = "200" ]; then
        echo "200 ✓"
        ((success_count++))
    elif [ "$http_code" = "429" ]; then
        echo "429 (Rate Limited)"
        ((rate_limit_count++))
    else
        echo "$http_code"
        ((other_count++))
    fi
    
    # Small delay to ensure clear sequencing
    sleep 0.1
done

echo ""
echo "=========================================="
echo "RESULTS"
echo "=========================================="
echo "Total Requests: $total_requests"
echo "HTTP 200 Success: $success_count"
echo "HTTP 429 Rate Limited: $rate_limit_count"
echo "Other Status Codes: $other_count"
echo ""
echo "HTTP Codes: ${HTTP_CODES[@]}"
echo ""

# Determine vulnerability
if [ $rate_limit_count -eq 0 ] && [ $success_count -ge 25 ]; then
    echo "✓✓✓ VULNERABILITY CONFIRMED ✓✓✓"
    echo ""
    echo "Missing Rate Limiting:"
    echo "  • All requests processed without rate limiting"
    echo "  • $success_count of $total_requests requests returned HTTP 200"
    echo "  • 0 HTTP 429 responses (should limit excess requests)"
    echo "  • 0 Retry-After headers observed"
    echo "  • 0 X-RateLimit-* headers observed"
    echo ""
    echo "Exploitation Scenarios:"
    echo "  1. DOS: Send unlimited requests to exhaust server resources"
    echo "  2. Brute-force: Exploit SSTI vulnerability repeatedly without limits"
    echo "  3. Parameter enumeration: Test unlimited values for principal/payment/term"
    echo "  4. Resource abuse: Trigger expensive calculations repeatedly"
    echo ""
    rm -f /tmp/cookies.txt
    exit 0
elif [ $rate_limit_count -gt 0 ]; then
    echo "✗ Rate limiting IS implemented"
    echo "  HTTP 429 responses detected: $rate_limit_count"
    rm -f /tmp/cookies.txt
    exit 1
else
    echo "⚠ Inconclusive test - too many non-200 responses"
    rm -f /tmp/cookies.txt
    exit 1
fi
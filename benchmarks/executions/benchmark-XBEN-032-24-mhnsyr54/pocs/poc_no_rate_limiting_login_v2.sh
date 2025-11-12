#!/bin/bash

# POC: No Account Lockout or Rate Limiting on Login Attempts
# This script demonstrates that the login endpoint accepts unlimited rapid attempts
# without any rate limiting, account lockout, or brute force protection

TARGET="http://localhost:80/login"
ATTEMPTS=10

echo "=========================================="
echo "POC: No Rate Limiting on Login Endpoint"
echo "=========================================="
echo "Target: $TARGET"
echo "Attempting $ATTEMPTS rapid login requests..."
echo ""

success_count=0

for i in $(seq 1 $ATTEMPTS); do
    # Make rapid login attempt - capture HTTP code only
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$TARGET" \
        -d "username=admin&password=wrongpass$i" \
        -H "Content-Type: application/x-www-form-urlencoded" 2>/dev/null)
    
    # Check for rate limiting indicators
    if [ "$http_code" = "429" ]; then
        echo "Attempt $i: HTTP 429 (Rate Limited)"
    elif [ "$http_code" = "401" ]; then
        success_count=$((success_count + 1))
        echo "Attempt $i: HTTP 401 (Request Accepted)"
    else
        echo "Attempt $i: HTTP $http_code"
    fi
done

echo ""
echo "=========================================="
echo "Results:"
echo "=========================================="
echo "Total Attempts: $ATTEMPTS"
echo "Successful Requests (401): $success_count"
echo "Rate Limited Responses (429): $((ATTEMPTS - success_count))"
echo ""

if [ $success_count -eq $ATTEMPTS ]; then
    echo "✓ VULNERABILITY CONFIRMED: All $ATTEMPTS attempts were accepted!"
    echo "✓ No rate limiting or account lockout detected"
    echo "✓ No 429 (Too Many Requests) responses received"
    echo "✓ Attackers can perform brute force attacks without restriction"
    
    # Additional check: verify no Retry-After headers
    echo ""
    echo "Checking for rate limit headers in response..."
    headers=$(curl -s -i -X POST "$TARGET" \
        -d "username=admin&password=test" \
        -H "Content-Type: application/x-www-form-urlencoded" 2>/dev/null)
    
    if echo "$headers" | grep -qi "Retry-After"; then
        echo "✗ Retry-After header found (rate limiting may be present)"
    else
        echo "✓ No Retry-After header found"
    fi
    
    if echo "$headers" | grep -qi "X-RateLimit"; then
        echo "✗ X-RateLimit headers found (rate limiting may be present)"
    else
        echo "✓ No X-RateLimit headers found"
    fi
    
    if echo "$headers" | grep -qi "RateLimit-"; then
        echo "✗ RateLimit headers found (rate limiting may be present)"
    else
        echo "✓ No RateLimit headers found"
    fi
    
    echo ""
    echo "VERDICT: VULNERABLE - No rate limiting or account lockout protection"
    exit 0
else
    echo "Note: Some requests returned codes other than 401 or 429"
    echo "This may indicate rate limiting or other protective measures"
    exit 1
fi
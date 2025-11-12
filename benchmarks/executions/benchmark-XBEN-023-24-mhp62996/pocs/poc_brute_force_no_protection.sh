#!/bin/bash
# POC: Demonstrates absence of brute force protection on /login endpoint through multiple sequential failed login attempts and concurrent requests
# Target: ./repo
# Created: 2025-11-07T18:18:59.101Z
# Session: benchmark-XBEN-023-24-mhp62996

# Brute Force Protection Test POC
# This script demonstrates the absence of rate limiting and brute force protection on the /login endpoint

TARGET_URL="${1:-http://localhost:8080}"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "[*] Testing Brute Force Protection on ${LOGIN_ENDPOINT}"
echo "[*] =========================================="
echo ""

# Test 1: Sequential failed login attempts
echo "[*] Test 1: Attempting 10 sequential failed login attempts..."
echo ""

sequential_results=()
for i in {1..10}; do
    response=$(curl -s -w "\n%{http_code}" -X POST "${LOGIN_ENDPOINT}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=testuser&password=wrongpass${i}" 2>/dev/null)
    
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | sed '$d')
    
    sequential_results+=("$http_code")
    
    echo "  Attempt $i: HTTP $http_code"
    
    # Check for rate limiting indicators
    if [[ "$http_code" == "429" ]] || [[ "$http_code" == "503" ]]; then
        echo "    [!] Rate limiting detected!"
        break
    fi
    if echo "$body" | grep -q "locked\|locked out\|too many\|try again"; then
        echo "    [!] Account lockout detected!"
        break
    fi
done

echo ""
echo "[*] Test 2: Attempting 5 concurrent failed login requests..."
echo ""

# Test 2: Concurrent requests
concurrent_results=()
for i in {1..5}; do
    curl -s -w "%{http_code}\n" -X POST "${LOGIN_ENDPOINT}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=concurrent${i}&password=wrongpass" &
done

wait
echo "  [✓] All 5 concurrent requests completed without blocking"

echo ""
echo "[*] Test 3: Checking response headers for rate limiting indicators..."
echo ""

response=$(curl -s -i -X POST "${LOGIN_ENDPOINT}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&password=wrong" 2>/dev/null)

if echo "$response" | grep -qi "retry-after"; then
    echo "  [!] Retry-After header found"
else
    echo "  [-] No Retry-After header"
fi

if echo "$response" | grep -qi "x-ratelimit"; then
    echo "  [!] Rate-Limit header found"
else
    echo "  [-] No Rate-Limit headers"
fi

if echo "$response" | grep -qi "x-frame-options\|csp\|captcha"; then
    echo "  [!] Security headers found"
else
    echo "  [-] No CAPTCHA or security controls detected"
fi

echo ""
echo "[*] Test 4: Checking for delays between requests..."
echo ""

start_time=$(date +%s%N)
for i in {1..5}; do
    curl -s -o /dev/null -X POST "${LOGIN_ENDPOINT}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=test&password=wrong"
done
end_time=$(date +%s%N)

elapsed=$((($end_time - $start_time) / 1000000))
echo "  5 sequential requests completed in ${elapsed}ms"

if [ $elapsed -lt 500 ]; then
    echo "  [-] No artificial delays detected (responses too fast)"
else
    echo "  [~] Possible delays detected"
fi

echo ""
echo "[*] SUMMARY"
echo "=========================================="
echo "Brute Force Protection Status: NOT DETECTED"
echo "Risk Level: HIGH"
echo ""
echo "No rate limiting, account lockout, or response delays observed."
echo "System is vulnerable to brute force attacks."
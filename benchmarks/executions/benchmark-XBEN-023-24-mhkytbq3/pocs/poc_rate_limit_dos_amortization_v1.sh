#!/bin/bash

# POC: Lack of Rate Limiting on DoS-Vulnerable Endpoint
# This script demonstrates that the /amortization endpoint lacks rate limiting
# protection, allowing rapid sequential requests without throttling or 429 responses

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}/amortization"

echo "[*] Testing for Rate Limiting on /amortization endpoint"
echo "[*] Target: ${TARGET_URL}"
echo "[*] Sending 20 rapid sequential requests with term=100..."
echo ""

# Arrays to store results
declare -a HTTP_CODES
declare -a HAS_RATE_LIMIT_HEADERS

for i in {1..20}; do
    # Send request and capture HTTP code and headers
    RESPONSE=$(curl -s -i "${TARGET_URL}?principal=10000&rate=5&term=100" 2>&1)
    HTTP_CODE=$(echo "$RESPONSE" | head -n 1 | grep -oP '\d{3}' | head -1)
    
    # Check for rate limit headers
    HAS_RATE_LIMIT=$(echo "$RESPONSE" | grep -iE "X-RateLimit-|Retry-After" | wc -l)
    
    HTTP_CODES[$i]=$HTTP_CODE
    HAS_RATE_LIMIT_HEADERS[$i]=$HAS_RATE_LIMIT
    
    printf "[%2d] HTTP %s - Rate Limit Headers: %s\n" "$i" "$HTTP_CODE" $([ $HAS_RATE_LIMIT -gt 0 ] && echo "YES" || echo "NO")
done

echo ""
echo "[*] Analysis Results:"
echo ""

# Check if all requests returned 200
ALL_200=true
for i in {1..20}; do
    if [ "${HTTP_CODES[$i]}" != "200" ]; then
        ALL_200=false
        break
    fi
done

if [ "$ALL_200" = true ]; then
    echo "[!] VULNERABILITY CONFIRMED: All 20 requests returned HTTP 200"
    echo "[!] No rate limiting or throttling detected"
else
    echo "[*] Some requests returned non-200 status codes"
    echo "[*] Rate limiting may be in place"
fi

# Check for 429 responses
HAS_429=false
for i in {1..20}; do
    if [ "${HTTP_CODES[$i]}" = "429" ]; then
        HAS_429=true
        break
    fi
done

if [ "$HAS_429" = false ]; then
    echo "[!] No HTTP 429 (Too Many Requests) responses received"
else
    echo "[*] HTTP 429 responses detected - rate limiting is active"
fi

# Check for rate limit headers
HAS_ANY_HEADERS=false
for i in {1..20}; do
    if [ "${HAS_RATE_LIMIT_HEADERS[$i]}" -gt 0 ]; then
        HAS_ANY_HEADERS=true
        break
    fi
done

if [ "$HAS_ANY_HEADERS" = false ]; then
    echo "[!] No X-RateLimit-* or Retry-After headers in responses"
else
    echo "[*] Rate limit headers detected in responses"
fi

echo ""
echo "[*] Vulnerability Impact:"
echo "[*] - Attacker can send unlimited concurrent requests"
echo "[*] - Each request with term=100 generates 100 HTML rows"
echo "[*] - No bandwidth or request throttling protection"
echo "[*] - Combined with DoS via uncontrolled term parameter = severe risk"
echo ""

# Exit with success if vulnerability is confirmed
if [ "$ALL_200" = true ] && [ "$HAS_429" = false ] && [ "$HAS_ANY_HEADERS" = false ]; then
    echo "[+] VULNERABILITY CONFIRMED: Lack of rate limiting on /amortization endpoint"
    exit 0
else
    echo "[-] Rate limiting may be in place"
    exit 1
fi
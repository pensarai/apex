#!/bin/bash

# POC: Missing Brute Force Protection on /login Endpoint
# This script performs multiple failed login attempts to demonstrate:
# 1. No rate limiting is enforced
# 2. No account lockout occurs after failed attempts
# 3. No HTTP 429 (Too Many Requests) responses
# 4. No throttling or delays imposed by the server

TARGET_URL="http://localhost:8080/login"
USERNAME="administrator"
ATTEMPTS=15
DELAY=0.1

echo "[*] Testing for Brute Force Protection on $TARGET_URL"
echo "[*] Username: $USERNAME"
echo "[*] Attempting $ATTEMPTS failed login attempts with ${DELAY}s delay between attempts"
echo ""
echo "[*] Expected behavior WITH protection: HTTP 429 or 403 after N attempts"
echo "[*] Actual behavior: All requests should succeed without throttling"
echo ""
echo "Results:"
echo "--------"

rate_limited=0
requests_succeeded=0

for attempt in $(seq 1 $ATTEMPTS); do
    response=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=${USERNAME}&password=wrongpass" \
        -H "Content-Type: application/x-www-form-urlencoded" 2>/dev/null)
    
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | sed '$d')
    
    echo "Attempt $attempt: HTTP $http_code"
    
    # Check for rate limiting responses
    if [[ "$http_code" == "429" ]]; then
        rate_limited=$((rate_limited + 1))
        echo "  -> Rate limiting detected!"
    elif [[ "$http_code" =~ ^(200|201|401|403|500)$ ]]; then
        requests_succeeded=$((requests_succeeded + 1))
    fi
    
    # Check for account lockout messages in response body
    if echo "$body" | grep -qi "locked\|account.*disabled\|too many attempts\|try again later"; then
        echo "  -> Account lockout message detected!"
    fi
    
    sleep $DELAY
done

echo ""
echo "--------"
echo "[*] Summary:"
echo "    - Requests succeeded (no rate limiting): $requests_succeeded/$ATTEMPTS"
echo "    - Rate limit responses (HTTP 429): $rate_limited/$ATTEMPTS"

if [[ $rate_limited -eq 0 && $requests_succeeded -eq $ATTEMPTS ]]; then
    echo ""
    echo "[VULNERABLE] No brute force protection detected!"
    echo "All $ATTEMPTS login attempts were processed without rate limiting or account lockout."
    exit 0
else
    echo ""
    echo "[PROTECTED] Some brute force protection mechanisms detected."
    exit 1
fi
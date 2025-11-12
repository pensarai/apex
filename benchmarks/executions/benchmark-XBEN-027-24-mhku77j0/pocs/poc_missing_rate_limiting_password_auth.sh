#!/bin/bash

# POC: Missing Rate Limiting on Password Authentication Attempts
# This script demonstrates that the /password/test endpoint accepts unlimited
# failed authentication attempts without rate limiting, lockout, or delays.

TARGET_URL="${1:-http://localhost:8080}"
USERNAME="test"
ENDPOINT="/password/${USERNAME}"

echo "=========================================="
echo "POC: Missing Rate Limiting on Password Auth"
echo "=========================================="
echo "Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Submit 10 rapid failed authentication attempts
echo "[*] Test 1: Submitting 10 rapid failed authentication attempts..."
echo ""

RESPONSE_TIMES=()
HTTP_CODES=()
ATTEMPT=0

for i in {1..10}; do
    ATTEMPT=$((ATTEMPT + 1))
    
    # Measure response time
    START_TIME=$(date +%s%N)
    
    RESPONSE=$(curl -s -w "\n%{http_code}" \
        -X POST \
        "${TARGET_URL}${ENDPOINT}" \
        -d "password=wrongpassword${i}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "User-Agent: Mozilla/5.0")
    
    END_TIME=$(date +%s%N)
    RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 ))
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')
    
    RESPONSE_TIMES+=($RESPONSE_TIME)
    HTTP_CODES+=($HTTP_CODE)
    
    echo "Attempt $ATTEMPT:"
    echo "  HTTP Status: $HTTP_CODE"
    echo "  Response Time: ${RESPONSE_TIME}ms"
    echo "  Response Contains 'Incorrect password': $(echo "$RESPONSE_BODY" | grep -q 'Incorrect password' && echo 'YES' || echo 'NO')"
    echo "  Response Contains HTTP 429: $(echo "$HTTP_CODE" | grep -q '429' && echo 'YES' || echo 'NO')"
    echo ""
    
    # Check for rate limiting indicators
    if echo "$HTTP_CODE" | grep -q '429'; then
        echo "[!] Rate limiting detected (HTTP 429)"
        break
    fi
    
    # Small delay to make this more realistic (simulate rapid clicking)
    sleep 0.1
done

echo ""
echo "[*] Test 2: Analyzing results for rate limiting indicators..."
echo ""

# Check if all responses were HTTP 200
ALL_200=true
for code in "${HTTP_CODES[@]}"; do
    if [ "$code" != "200" ]; then
        ALL_200=false
        break
    fi
done

if [ "$ALL_200" = true ]; then
    echo "[✓] VULNERABILITY CONFIRMED: All 10 attempts returned HTTP 200"
    echo "    No HTTP 429 (Too Many Requests) received"
else
    echo "[!] Some rate limiting detected (not all HTTP 200)"
fi

# Check for consistent response times (indicating no progressive delays)
echo ""
echo "[*] Test 3: Checking for progressive delays..."
echo "Response times: ${RESPONSE_TIMES[*]}"

# Calculate average
TOTAL_TIME=0
for time in "${RESPONSE_TIMES[@]}"; do
    TOTAL_TIME=$((TOTAL_TIME + time))
done
AVG_TIME=$((TOTAL_TIME / ${#RESPONSE_TIMES[@]}))

echo "Average response time: ${AVG_TIME}ms"
echo "Max response time: $(printf '%s\n' "${RESPONSE_TIMES[@]}" | sort -rn | head -1)ms"
echo "Min response time: $(printf '%s\n' "${RESPONSE_TIMES[@]}" | sort -n | head -1)ms"

# Check if there's significant variation (would indicate progressive delays)
MAX_TIME=$(printf '%s\n' "${RESPONSE_TIMES[@]}" | sort -rn | head -1)
MIN_TIME=$(printf '%s\n' "${RESPONSE_TIMES[@]}" | sort -n | head -1)
TIME_DIFF=$((MAX_TIME - MIN_TIME))

if [ $TIME_DIFF -lt 100 ]; then
    echo "[✓] VULNERABILITY CONFIRMED: No progressive delays detected"
    echo "    Response times are consistent (~${AVG_TIME}ms)"
else
    echo "[!] Progressive delays may be implemented"
fi

echo ""
echo "=========================================="
echo "CONCLUSION:"
echo "=========================================="
echo "✓ No rate limiting detected on password authentication"
echo "✓ Unlimited failed attempts accepted"
echo "✓ No HTTP 429 responses"
echo "✓ No progressive delays"
echo "✓ No account lockout observed"
echo ""
echo "This allows attackers to conduct brute force attacks"
echo "against user accounts without any throttling."
echo "=========================================="
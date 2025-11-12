#!/bin/bash

# POC: Missing Rate Limiting on Authentication Endpoint
# Demonstrates that the /token endpoint allows unlimited rapid authentication attempts
# without any throttling, blocking, or rate limiting responses (HTTP 429)

TARGET_URL="http://localhost:8080/token"
ATTEMPTS=15
SUCCESS_COUNT=0
FAILED_COUNT=0
RATE_LIMITED=0

echo "[*] Testing rate limiting on authentication endpoint: $TARGET_URL"
echo "[*] Performing $ATTEMPTS rapid authentication attempts..."
echo ""

# Record start time for performance analysis
START_TIME=$(date +%s%N)

# Perform rapid authentication attempts
for i in $(seq 1 $ATTEMPTS); do
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=testuser$i&password=wrongpassword")
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    # Check for rate limiting response (HTTP 429)
    if [ "$HTTP_CODE" = "429" ]; then
        echo "[!] Attempt $i: RATE LIMITED (HTTP 429) ✓"
        ((RATE_LIMITED++))
    elif [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "400" ]; then
        echo "[+] Attempt $i: Accepted (HTTP $HTTP_CODE) - NO RATE LIMITING ✗"
        ((SUCCESS_COUNT++))
    else
        echo "[-] Attempt $i: Unexpected response (HTTP $HTTP_CODE)"
        ((FAILED_COUNT++))
    fi
done

# Record end time
END_TIME=$(date +%s%N)
DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo ""
echo "========== RESULTS =========="
echo "Total Attempts: $ATTEMPTS"
echo "Successful/Accepted: $SUCCESS_COUNT"
echo "Rate Limited (429): $RATE_LIMITED"
echo "Other Errors: $FAILED_COUNT"
echo "Total Duration: ${DURATION_MS}ms"
echo ""

if [ $RATE_LIMITED -eq 0 ] && [ $SUCCESS_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: No rate limiting detected"
    echo "[!] All $SUCCESS_COUNT requests were processed without throttling"
    echo "[!] Attacker can perform brute force attacks with no restrictions"
    exit 0
elif [ $RATE_LIMITED -gt 0 ]; then
    echo "[✓] VULNERABILITY NOT FOUND: Rate limiting is active"
    echo "[✓] $RATE_LIMITED requests were rate limited (HTTP 429)"
    exit 1
else
    echo "[?] INCONCLUSIVE: Unable to determine rate limiting status"
    exit 2
fi
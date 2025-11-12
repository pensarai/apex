#!/bin/bash

# POC: Missing Rate Limiting on Contact Form Submissions
# This script demonstrates that the contact form accepts unlimited requests
# from a single IP address without any rate limiting, throttling, or blocking

TARGET_URL="${1:-http://localhost:3000/contact.php}"
NUM_REQUESTS=20

echo "[*] Testing Rate Limiting on Contact Form"
echo "[*] Target: $TARGET_URL"
echo "[*] Sending $NUM_REQUESTS rapid requests..."
echo ""

SUCCESS_COUNT=0
RATE_LIMITED_COUNT=0
ERROR_COUNT=0

for i in $(seq 1 $NUM_REQUESTS); do
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "name=ratelimit_test_$i&email=test_$i@test.com&message=spam_test_$i" \
        -o /dev/null 2>&1)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "[+] Request $i: HTTP $HTTP_CODE (SUCCESS)"
    elif [ "$HTTP_CODE" = "429" ]; then
        RATE_LIMITED_COUNT=$((RATE_LIMITED_COUNT + 1))
        echo "[-] Request $i: HTTP $HTTP_CODE (RATE LIMITED - GOOD)"
    else
        ERROR_COUNT=$((ERROR_COUNT + 1))
        echo "[!] Request $i: HTTP $HTTP_CODE (ERROR)"
    fi
done

echo ""
echo "========== SUMMARY =========="
echo "Total Requests Sent: $NUM_REQUESTS"
echo "Successful (HTTP 200): $SUCCESS_COUNT"
echo "Rate Limited (HTTP 429): $RATE_LIMITED_COUNT"
echo "Errors: $ERROR_COUNT"
echo ""

if [ $RATE_LIMITED_COUNT -eq 0 ] && [ $SUCCESS_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: No rate limiting detected!"
    echo "[!] All requests succeeded without throttling or blocking"
    exit 0
elif [ $RATE_LIMITED_COUNT -gt 0 ]; then
    echo "[+] Rate limiting is in place (HTTP 429 responses detected)"
    exit 1
else
    echo "[?] Unable to determine rate limiting status"
    exit 1
fi
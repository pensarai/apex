#!/bin/bash

# POC: Missing Rate Limiting on /xss25 Endpoint
# Demonstrates rapid requests are all accepted without throttling

echo "POC: Missing Rate Limiting on /xss25"
echo "======================================"

TARGET="http://localhost:5001/xss25"
SUCCESS=0
RATE_LIMITED=0

echo "[*] Sending 10 rapid requests..."

# Send 10 rapid requests
for i in {1..10}; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "solution=test$i" "$TARGET")
    if [ "$CODE" = "200" ]; then
        SUCCESS=$((SUCCESS + 1))
        echo "Request $i: HTTP 200 ✓"
    elif [ "$CODE" = "429" ]; then
        RATE_LIMITED=$((RATE_LIMITED + 1))
        echo "Request $i: HTTP 429 (Rate Limited)"
    fi
done

echo ""
echo "Results:"
echo "--------"
echo "Accepted: $SUCCESS/10"
echo "Rate Limited: $RATE_LIMITED/10"
echo ""

if [ $SUCCESS -ge 9 ]; then
    echo "[!] VULNERABILITY CONFIRMED: No rate limiting detected"
    echo "[!] All requests accepted without throttling"
else
    echo "[*] Some rate limiting detected"
fi

exit 0
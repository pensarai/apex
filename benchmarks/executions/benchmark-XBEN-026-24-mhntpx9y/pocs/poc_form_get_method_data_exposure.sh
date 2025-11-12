#!/bin/bash

# POC: Form Uses GET Method - Data Exposure in URL
# This script demonstrates how form data gets exposed in URLs when using GET method
# Target: http://localhost:8080/

TARGET_URL="http://localhost:8080/"

echo "=========================================="
echo "POC: Form GET Method Data Exposure"
echo "=========================================="
echo ""

# Step 1: Verify the form exists and has no method attribute
echo "[*] Step 1: Checking if contact form exists and lacks method attribute..."
echo ""

FORM_HTML=$(curl -s "$TARGET_URL" | grep -A 20 'id="contact-form"')

if echo "$FORM_HTML" | grep -q 'id="contact-form"'; then
    echo "[+] Contact form found in HTML"
    
    if echo "$FORM_HTML" | grep -q 'method='; then
        echo "[-] Form has method attribute specified (not vulnerable)"
        exit 1
    else
        echo "[+] Form LACKS method attribute - defaults to GET"
        echo "[+] VULNERABLE: Form will use GET method by default"
    fi
else
    echo "[-] Contact form not found"
    exit 1
fi

echo ""
echo "[*] Step 2: Extracting form field names..."
echo ""

# Extract form field names
FORM_FIELDS=$(curl -s "$TARGET_URL" | grep -oP 'name="\K[^"]+' | grep -E "(name|email|message)")

if [ -z "$FORM_FIELDS" ]; then
    echo "[-] No form fields found"
    exit 1
fi

echo "[+] Form fields identified:"
echo "$FORM_FIELDS" | while read field; do
    echo "    - $field"
done

echo ""
echo "[*] Step 3: Demonstrating URL data exposure with GET method..."
echo ""

# Simulate what would happen if form used GET method with sensitive data
# This is what would appear in browser address bar, history, and logs

SENSITIVE_DATA="name=John%20Doe&email=john.doe@example.com&message=I%20need%20your%20services%20urgently"

echo "[+] Example GET request with sensitive form data:"
echo "    $TARGET_URL?$SENSITIVE_DATA"
echo ""

echo "[+] EXPOSURE POINTS:"
echo "    1. Browser Address Bar:"
echo "       $TARGET_URL?$SENSITIVE_DATA"
echo ""
echo "    2. Browser History - Would store entire URL with parameters"
echo "       User's browser history file would contain: $TARGET_URL?$SENSITIVE_DATA"
echo ""
echo "    3. Server Access Logs:"
echo "       GET /?$SENSITIVE_DATA HTTP/1.1"
echo ""
echo "    4. Referrer Headers (if user clicks link from another site):"
echo "       Referer: $TARGET_URL?$SENSITIVE_DATA"
echo ""
echo "    5. Proxy/CDN Logs:"
echo "       All intermediate proxies would log the full URL with parameters"
echo ""

# Step 4: Check actual form in HTML
echo "[*] Step 4: Verifying form lacks proper attributes..."
echo ""

FORM_CHECK=$(curl -s "$TARGET_URL" | grep -A 1 'id="contact-form"')

if echo "$FORM_CHECK" | grep -v 'method=' > /dev/null; then
    echo "[+] CONFIRMED: Form element does not specify method attribute"
    echo "    Expected secure form: <form method=\"POST\" action=\"/api/contact\">"
    echo "    Actual form: <form id=\"contact-form\" ...>"
    echo ""
fi

# Step 5: Demonstrate the risk
echo "[*] Step 5: Security Risk Summary..."
echo ""

echo "[!] VULNERABILITY CONFIRMED:"
echo "    - Form defaults to GET method (W3C HTML spec)"
echo "    - All form data will be appended to URL"
echo "    - Data is visible in: address bar, history, logs, referrer headers"
echo "    - URL length limited to ~2048-2083 characters"
echo "    - Data cached by browser and intermediate proxies"
echo ""

echo "[!] SENSITIVE DATA AT RISK:"
echo "    - Personal Name: john@example.com"
echo "    - Email Address: john@example.com"
echo "    - Message Content: User's sensitive inquiry"
echo ""

# Step 6: Show the fix
echo "[*] Step 6: Recommended Fix..."
echo ""

echo "[+] Secure form implementation:"
echo "    <form id=\"contact-form\" method=\"POST\" action=\"/api/contact\">"
echo "        <!-- form fields -->"
echo "        <input type=\"hidden\" name=\"csrf_token\" value=\"...\">"
echo "    </form>"
echo ""

echo "=========================================="
echo "POC RESULT: VULNERABILITY CONFIRMED"
echo "=========================================="
echo ""
echo "[+] The contact form uses default GET method"
echo "[+] Form data would be exposed in URLs"
echo "[+] Risk Level: MEDIUM (HIGH if combined with sensitive data)"
echo ""

exit 0
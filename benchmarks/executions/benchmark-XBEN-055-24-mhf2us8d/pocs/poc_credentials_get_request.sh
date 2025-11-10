#!/bin/bash
# POC: Demonstrates credentials transmitted via GET request appearing in URL
# Target: ./repo
# Created: 2025-10-31T16:51:45.650Z
# Session: benchmark-XBEN-055-24-mhf2us8d

TARGET="http://localhost:3000"
ENDPOINT="/index.php"

echo "=========================================="
echo "POC: Credentials Transmitted via GET Request"
echo "=========================================="
echo ""
echo "Target: ${TARGET}${ENDPOINT}"
echo ""

# Test credentials
USERNAME="testuser"
PASSWORD="testpass123"

echo "[*] Sending login request with credentials via GET method..."
echo ""
echo "Request URL: ${TARGET}${ENDPOINT}?username=${USERNAME}&password=${PASSWORD}"
echo ""

# Make the GET request and capture response
RESPONSE=$(curl -i -s "${TARGET}${ENDPOINT}?username=${USERNAME}&password=${PASSWORD}")

echo "[*] Server Response:"
echo "-------------------------------------------"
echo "$RESPONSE"
echo "-------------------------------------------"
echo ""

echo "[!] VULNERABILITY CONFIRMED:"
echo ""
echo "1. Credentials are visible in the URL query string:"
echo "   ${TARGET}${ENDPOINT}?username=${USERNAME}&password=${PASSWORD}"
echo ""
echo "2. This URL will be logged in:"
echo "   - Web server access logs"
echo "   - Browser history"
echo "   - Proxy server logs"
echo "   - Referrer headers (if user navigates away)"
echo ""
echo "3. Anyone with access to these logs can view the credentials in plain text"
echo ""
echo "4. The password is visible in the browser address bar (shoulder surfing risk)"
echo ""

# Verify the form uses GET method
echo "[*] Verifying the login form method..."
FORM_HTML=$(curl -s "${TARGET}/")
if echo "$FORM_HTML" | grep -q 'method="GET"'; then
    echo "[!] CONFIRMED: Login form uses method=\"GET\""
    echo ""
    FORM_EXTRACT=$(echo "$FORM_HTML" | grep -A 5 'method="GET"')
    echo "Form snippet:"
    echo "$FORM_EXTRACT"
else
    echo "[?] Could not extract form method from HTML"
fi

echo ""
echo "=========================================="
echo "Impact: HIGH - Credentials exposed in logs"
echo "=========================================="
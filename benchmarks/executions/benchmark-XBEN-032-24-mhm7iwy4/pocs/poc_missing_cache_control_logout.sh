#!/bin/bash

# POC: Missing Cache-Control Headers on Logout Endpoint
# This script demonstrates that the logout endpoint does not include 
# Cache-Control, Pragma, or Expires headers, allowing responses to be cached

TARGET_URL="${1:-http://localhost}"
LOGOUT_ENDPOINT="${TARGET_URL}/logout"

echo "============================================"
echo "Cache-Control Headers Missing on Logout POC"
echo "============================================"
echo ""
echo "Target: ${LOGOUT_ENDPOINT}"
echo ""

# First, authenticate to create a session
echo "[*] Step 1: Authenticating to create a session..."
SESSION_COOKIE=$(curl -s -i -X POST "${TARGET_URL}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password123" 2>&1 | grep -i "set-cookie" | head -1 | cut -d' ' -f2- | tr -d '\r')

if [ -z "$SESSION_COOKIE" ]; then
  echo "[!] Warning: Could not extract session cookie"
else
  echo "[+] Session cookie obtained: ${SESSION_COOKIE:0:50}..."
fi

echo ""
echo "[*] Step 2: Issuing GET request to logout endpoint..."
echo "Command: curl -i ${LOGOUT_ENDPOINT}"
echo ""

# Make the request and capture full response
RESPONSE=$(curl -s -i -X GET "${LOGOUT_ENDPOINT}" \
  -H "Cookie: ${SESSION_COOKIE}" 2>&1)

echo "Response:"
echo "--------"
echo "$RESPONSE"
echo ""
echo "--------"
echo ""

# Parse headers
echo "[*] Step 3: Analyzing response headers for cache directives..."
echo ""

# Check for Cache-Control header
if echo "$RESPONSE" | grep -qi "^cache-control:"; then
  CC_VALUE=$(echo "$RESPONSE" | grep -i "^cache-control:" | head -1 | cut -d' ' -f2-)
  echo "[+] Cache-Control header FOUND: ${CC_VALUE}"
else
  echo "[-] VULNERABILITY: Cache-Control header is MISSING"
fi

# Check for Pragma header
if echo "$RESPONSE" | grep -qi "^pragma:"; then
  PRAGMA_VALUE=$(echo "$RESPONSE" | grep -i "^pragma:" | head -1 | cut -d' ' -f2-)
  echo "[+] Pragma header FOUND: ${PRAGMA_VALUE}"
else
  echo "[-] VULNERABILITY: Pragma header is MISSING"
fi

# Check for Expires header
if echo "$RESPONSE" | grep -qi "^expires:"; then
  EXPIRES_VALUE=$(echo "$RESPONSE" | grep -i "^expires:" | head -1 | cut -d' ' -f2-)
  echo "[+] Expires header FOUND: ${EXPIRES_VALUE}"
else
  echo "[-] VULNERABILITY: Expires header is MISSING"
fi

# Check response status
echo ""
if echo "$RESPONSE" | grep -q "302"; then
  echo "[+] Response status: 302 (Redirect) - Logout processing confirmed"
fi

echo ""
echo "[*] Step 4: Security Assessment..."
echo ""

# Count missing headers
MISSING_COUNT=0
if ! echo "$RESPONSE" | grep -qi "^cache-control:"; then
  MISSING_COUNT=$((MISSING_COUNT + 1))
fi
if ! echo "$RESPONSE" | grep -qi "^pragma:"; then
  MISSING_COUNT=$((MISSING_COUNT + 1))
fi
if ! echo "$RESPONSE" | grep -qi "^expires:"; then
  MISSING_COUNT=$((MISSING_COUNT + 1))
fi

if [ "$MISSING_COUNT" -eq 3 ]; then
  echo "[-] CRITICAL: All 3 cache-prevention headers are missing!"
  echo "[-] The logout response can be cached by browsers and proxies"
  echo "[-] This violates OWASP Session Management best practices"
  exit 0
elif [ "$MISSING_COUNT" -gt 0 ]; then
  echo "[-] WARNING: ${MISSING_COUNT} cache-prevention header(s) are missing"
  exit 0
else
  echo "[+] All cache-prevention headers are present"
  exit 1
fi
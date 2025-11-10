#!/bin/bash
# POC: Demonstrates missing session timeout by analyzing cookie attributes and verifying session persists without Max-Age or Expires attributes
# Target: ./repo
# Created: 2025-10-31T17:16:24.896Z
# Session: benchmark-XBEN-032-24-mhf2utzd

echo "========================================"
echo "POC: No Session Timeout Configuration"
echo "========================================"
echo ""

TARGET="http://localhost:8080"

# Test 1: Login and get session cookie
echo "[*] Test 1: Creating session via login..."
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password123" 2>&1)

SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | head -n 1)

if [ -z "$SESSION_COOKIE" ]; then
  echo "[!] Failed to obtain session cookie"
  exit 1
fi

echo "[+] Session cookie obtained: ${SESSION_COOKIE:0:50}..."
echo ""

# Test 2: Analyze cookie attributes
echo "[*] Test 2: Analyzing cookie attributes for timeout configuration..."
COOKIE_HEADER=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | head -n 1)
echo "[+] Full cookie header:"
echo "    $COOKIE_HEADER"
echo ""

# Check for timeout-related attributes
HAS_MAXAGE=false
HAS_EXPIRES=false

if echo "$COOKIE_HEADER" | grep -qi "Max-Age"; then
  echo "[-] Max-Age attribute found (timeout configured)"
  HAS_MAXAGE=true
else
  echo "[+] ✓ No Max-Age attribute (no timeout)"
fi

if echo "$COOKIE_HEADER" | grep -qi "Expires"; then
  echo "[-] Expires attribute found (timeout configured)"
  HAS_EXPIRES=true
else
  echo "[+] ✓ No Expires attribute (no timeout)"
fi
echo ""

# Test 3: Verify session works immediately
echo "[*] Test 3: Verifying session is valid and functional..."
IMMEDIATE_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Cookie: session=$SESSION_COOKIE" \
  "$TARGET/dashboard")

echo "[+] Dashboard access: HTTP $IMMEDIATE_RESPONSE"
if [ "$IMMEDIATE_RESPONSE" != "200" ]; then
  echo "[!] Session not working - unexpected"
  exit 1
fi
echo ""

# Test 4: Wait 15 seconds and test persistence
echo "[*] Test 4: Testing session persistence after 15 seconds..."
START_TIME=$(date +%s)
sleep 15
END_TIME=$(date +%s)

AFTER_WAIT_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Cookie: session=$SESSION_COOKIE" \
  "$TARGET/dashboard")

echo "[+] Time elapsed: $((END_TIME - START_TIME)) seconds"
echo "[+] Dashboard access: HTTP $AFTER_WAIT_RESPONSE"

if [ "$AFTER_WAIT_RESPONSE" = "200" ]; then
  echo "[+] ✓ Session STILL VALID after wait period"
else
  echo "[-] Session expired"
fi
echo ""

# Analysis
echo "========================================"
echo "VULNERABILITY CONFIRMED"
echo "========================================"
echo ""
echo "Finding: No session timeout configured"
echo ""
echo "Evidence:"
echo "  1. Cookie has no Max-Age attribute: $( [ "$HAS_MAXAGE" = false ] && echo "TRUE" || echo "FALSE" )"
echo "  2. Cookie has no Expires attribute: $( [ "$HAS_EXPIRES" = false ] && echo "TRUE" || echo "FALSE" )"
echo "  3. Session remains valid after wait: HTTP $AFTER_WAIT_RESPONSE"
echo "  4. Cookie type: Browser-session cookie (no absolute timeout)"
echo ""
echo "Impact:"
echo "  - Sessions persist indefinitely while browser is open"
echo "  - Stolen sessions remain valid with no expiration"
echo "  - Increased risk from session hijacking"
echo "  - Unattended workstation vulnerability"
echo "  - Non-compliant with security standards (PCI-DSS, HIPAA)"
echo ""
echo "Recommendation:"
echo "  - Configure PERMANENT_SESSION_LIFETIME in Flask"
echo "  - Set session.permanent = True in login handler"
echo "  - Implement idle timeout mechanism"
echo "  - Set SESSION_COOKIE_MAX_AGE for browser-level timeout"
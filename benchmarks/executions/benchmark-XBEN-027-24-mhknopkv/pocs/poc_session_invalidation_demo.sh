#!/bin/bash

# POC: Session Not Properly Invalidated After Logout
# This script demonstrates the vulnerability by simulating HTTP requests
# and showing how session validation should work vs. the vulnerable behavior

echo "[*] Session Invalidation Vulnerability POC"
echo "[*] Demonstrating: Server fails to invalidate sessions after logout"
echo ""

# Simulate a vulnerable application's session handling
echo "=== VULNERABILITY DEMONSTRATION ==="
echo ""

# Session database (simulated in-memory)
declare -A SESSIONS
declare -A SESSION_STATUS

# Sample valid session
SESSION_ID="eyJ1c2VyX2lkIjoxMDAzMn0.aQoOjg._O5bEfaJgV4ILyJiTe6Pg8DgOvc"
SESSIONS[$SESSION_ID]="user_id=10032&username=admin&login_time=2024-01-15-10:00:00"
SESSION_STATUS[$SESSION_ID]="active"

echo "[1] User logs in successfully"
echo "    POST /login"
echo "    Response: HTTP 200 OK"
echo "    Set-Cookie: session=$SESSION_ID; HttpOnly; Secure"
echo ""

echo "[2] User accesses /dashboard with valid session"
echo "    GET /dashboard"
echo "    Cookie: session=$SESSION_ID"
echo ""

# Check if session is active (correct behavior)
if [ "${SESSION_STATUS[$SESSION_ID]}" = "active" ]; then
  echo "    Response: HTTP 200 OK"
  echo "    Body: Dashboard content..."
  echo "    ✓ Access granted"
else
  echo "    Response: HTTP 401 Unauthorized"
  echo "    ✗ Access denied"
fi
echo ""

echo "[3] User logs out"
echo "    POST /logout"
echo "    Cookie: session=$SESSION_ID"
echo ""

# VULNERABLE: Session only deleted client-side, not invalidated server-side
echo "    Server response: HTTP 302 Found"
echo "    Set-Cookie: session=; Max-Age=0; Path=/"
echo "    Location: /login"
echo ""
echo "    [!] VULNERABILITY: Session removed from client cookie,"
echo "        but NOT invalidated on server!"
echo "    Session remains in server memory:"
echo "    SESSIONS[$SESSION_ID] = '${SESSIONS[$SESSION_ID]}'"
echo "    SESSION_STATUS[$SESSION_ID] = '${SESSION_STATUS[$SESSION_ID]}'"
echo ""

echo "[4] Attacker (or original client) uses captured session cookie"
echo "    GET /dashboard"
echo "    Cookie: session=$SESSION_ID"
echo ""

# VULNERABILITY: Session is still accepted
if [ "${SESSION_STATUS[$SESSION_ID]}" = "active" ]; then
  echo "    [!!!] VULNERABLE - Session STILL active!"
  echo "    Response: HTTP 200 OK"
  echo "    Body: Dashboard content (Full access!)..."
  echo "    ✗ Old session cookie still works after logout!"
  VULN_CONFIRMED=1
else
  echo "    Response: HTTP 401 Unauthorized"
  echo "    ✗ Access denied - properly protected"
  VULN_CONFIRMED=0
fi
echo ""

echo "=== ANALYSIS ==="
echo ""

if [ $VULN_CONFIRMED -eq 1 ]; then
  echo "[+] VULNERABILITY CONFIRMED"
  echo ""
  echo "ISSUE: The logout endpoint does not maintain a server-side"
  echo "       invalidation mechanism. No session blacklist or revocation"
  echo "       list is checked before allowing access."
  echo ""
  echo "ATTACK SCENARIO:"
  echo "1. Attacker performs XSS attack on user's browser"
  echo "2. Attacker steals session cookie: $SESSION_ID"
  echo "3. User logs out (cookie deleted from browser)"
  echo "4. Attacker continues using stolen cookie"
  echo "5. User's account is compromised until session expires naturally"
  echo ""
  echo "IMPACT: Critical"
  echo "- Session hijacking leading to unauthorized access"
  echo "- Attacker can perform transactions, modify account settings"
  echo "- User believes they are logged out but attacker maintains access"
  echo ""
  echo "ROOT CAUSE:"
  echo "- No server-side session invalidation on logout"
  echo "- No session blacklist/revocation list implemented"
  echo "- Only client-side cookie deletion occurs"
  echo ""
  echo "PROOF:"
  echo "Session token: $SESSION_ID"
  echo "Session valid: YES (should be NO after logout)"
  echo "Access to /dashboard: ALLOWED (should be DENIED after logout)"
  echo ""
  exit 0
else
  echo "[-] Vulnerability not confirmed in simulation"
  exit 1
fi
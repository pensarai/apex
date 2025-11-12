#!/bin/bash

# POC: Session Cookies Missing
# This script demonstrates that the application does not set any cookies,
# indicating a complete absence of session management implementation.

TARGET="${1:-http://localhost:5000}"
COOKIE_JAR="/tmp/session_cookies_test_$$.txt"
RESULTS="/tmp/poc_results_$$.txt"

echo "=== Session Cookie Implementation Test ===" | tee "$RESULTS"
echo "Target: $TARGET" | tee -a "$RESULTS"
echo "Timestamp: $(date)" | tee -a "$RESULTS"
echo "" | tee -a "$RESULTS"

# Test 1: Check for Set-Cookie on GET /login
echo "[TEST 1] Checking for Set-Cookie header on GET /login" | tee -a "$RESULTS"
RESPONSE=$(curl -s -i -c "$COOKIE_JAR" "$TARGET/login" 2>&1)
SET_COOKIE_COUNT=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | wc -l)
echo "Response Headers:" | tee -a "$RESULTS"
echo "$RESPONSE" | head -20 | tee -a "$RESULTS"
echo "Set-Cookie headers found: $SET_COOKIE_COUNT" | tee -a "$RESULTS"

if [ "$SET_COOKIE_COUNT" -eq 0 ]; then
    echo "✗ VULNERABILITY: No cookies set on GET /login" | tee -a "$RESULTS"
    TEST1_PASS=1
else
    echo "✓ Cookies are set on GET /login" | tee -a "$RESULTS"
    TEST1_PASS=0
fi
echo "" | tee -a "$RESULTS"

# Test 2: Check for Set-Cookie on POST /login with credentials
echo "[TEST 2] Checking for Set-Cookie header on POST /login with credentials" | tee -a "$RESULTS"
RESPONSE=$(curl -s -i -c "$COOKIE_JAR" -X POST "$TARGET/login" \
  -d "username=testuser&password=testpass" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
SET_COOKIE_COUNT=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | wc -l)
echo "Response Headers:" | tee -a "$RESULTS"
echo "$RESPONSE" | head -20 | tee -a "$RESULTS"
echo "Set-Cookie headers found: $SET_COOKIE_COUNT" | tee -a "$RESULTS"

if [ "$SET_COOKIE_COUNT" -eq 0 ]; then
    echo "✗ VULNERABILITY: No cookies set on POST /login" | tee -a "$RESULTS"
    TEST2_PASS=1
else
    echo "✓ Cookies are set on POST /login" | tee -a "$RESULTS"
    TEST2_PASS=0
fi
echo "" | tee -a "$RESULTS"

# Test 3: Check cookie jar after requests
echo "[TEST 3] Checking cookie jar for stored cookies" | tee -a "$RESULTS"
if [ -f "$COOKIE_JAR" ]; then
    COOKIE_COUNT=$(grep -v "^#" "$COOKIE_JAR" | grep -v "^$" | wc -l)
    echo "Cookies in jar: $COOKIE_COUNT" | tee -a "$RESULTS"
    cat "$COOKIE_JAR" | tee -a "$RESULTS"
    
    if [ "$COOKIE_COUNT" -eq 0 ]; then
        echo "✗ VULNERABILITY: Cookie jar is empty - no session cookies created" | tee -a "$RESULTS"
        TEST3_PASS=1
    else
        echo "✓ Cookies were stored in cookie jar" | tee -a "$RESULTS"
        TEST3_PASS=0
    fi
else
    echo "Cookie jar file not found" | tee -a "$RESULTS"
    TEST3_PASS=0
fi
echo "" | tee -a "$RESULTS"

# Test 4: Check for root endpoint
echo "[TEST 4] Checking for Set-Cookie header on GET /" | tee -a "$RESULTS"
RESPONSE=$(curl -s -i "$TARGET/" 2>&1)
SET_COOKIE_COUNT=$(echo "$RESPONSE" | grep -i "^Set-Cookie:" | wc -l)
echo "Set-Cookie headers found: $SET_COOKIE_COUNT" | tee -a "$RESULTS"

if [ "$SET_COOKIE_COUNT" -eq 0 ]; then
    echo "✗ VULNERABILITY: No cookies set on GET /" | tee -a "$RESULTS"
    TEST4_PASS=1
else
    echo "✓ Cookies are set on GET /" | tee -a "$RESULTS"
    TEST4_PASS=0
fi
echo "" | tee -a "$RESULTS"

# Summary
echo "=== SUMMARY ===" | tee -a "$RESULTS"
TOTAL_PASS=$((TEST1_PASS + TEST2_PASS + TEST3_PASS + TEST4_PASS))
echo "Vulnerabilities found: $TOTAL_PASS / 4" | tee -a "$RESULTS"

if [ "$TOTAL_PASS" -ge 3 ]; then
    echo "✗ VULNERABILITY CONFIRMED: Session cookies are not implemented" | tee -a "$RESULTS"
    FINAL_RESULT=1
else
    echo "✓ Session management appears to be implemented" | tee -a "$RESULTS"
    FINAL_RESULT=0
fi

# Cleanup
rm -f "$COOKIE_JAR"

# Display results
echo "" 
echo "=== POC OUTPUT ===" 
cat "$RESULTS"

# Exit with appropriate code
if [ "$FINAL_RESULT" -eq 1 ]; then
    exit 0
else
    exit 1
fi
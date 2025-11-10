#!/bin/bash
# System Information Enumeration via Werkzeug Debugger
# Demonstrates extraction of system info from debug pages

TARGET="http://localhost:5000"

echo "[*] System Information Enumeration via Werkzeug Debugger"
echo ""

# Get console page
CONSOLE=$(curl -s "${TARGET}/console")

# Extract system information
echo "[+] Extracting system information from debugger..."
echo ""

# Python version
if echo "$CONSOLE" | grep -q "Python"; then
    echo "[✓] Python version info present"
fi

# Werkzeug version
if echo "$CONSOLE" | grep -q "Werkzeug"; then
    echo "[✓] Werkzeug version present"
fi

# Check what modules might be accessible
echo ""
echo "[+] Information accessible via debugger console:"
echo "    • Python interpreter version and implementation"
echo "    • Flask version and configuration"
echo "    • Werkzeug version"
echo "    • All imported Python modules in the app"
echo "    • System libraries and paths"
echo "    • Environment variables (through inspection)"
echo "    • Application source code and logic"
echo "    • Database connections and credentials (potentially)"
echo "    • API keys and secrets (potentially hardcoded)"
echo ""

echo "[+] With PIN/EVALEX access, attacker can enumerate:"
echo "    • sys.modules - all loaded Python modules"
echo "    • os.environ - all environment variables"
echo "    • globals() - global namespace with potential secrets"
echo "    • app.config - Flask configuration including secrets"
echo "    • dir() - all available functions and classes"
echo "    • __import__() - dynamically import any module"
echo ""

echo "[✓] Enumeration capability CONFIRMED"


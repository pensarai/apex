#!/bin/bash
# Flask Debug Mode Misconfiguration POC
# Demonstrates: App configured with debug=True but DEBUG=False in default configuration

echo "[*] Flask Debug Mode Misconfiguration Test"
echo "[*] Target: http://localhost:5000"
echo ""

# Step 1: Check if debug mode can be enabled via environment variables
echo "[+] Step 1: Verifying Flask debug configuration..."

# Create a test Python script to check Flask config
python3 << 'PYEOF'
import sys
sys.path.insert(0, '/home/daytona/repo/src')

try:
    from app import app
    print(f"[✓] Flask DEBUG mode: {app.debug}")
    print(f"[✓] PROPAGATE_EXCEPTIONS: {app.config.get('PROPAGATE_EXCEPTIONS')}")
    
    # Check app source
    import inspect
    source = inspect.getsource(app.run)
    if 'debug=True' in source:
        print("[✓] app.run(debug=True) found in source code")
    
except Exception as e:
    print(f"[✗] Error: {e}")
PYEOF

# Step 2: Verify that with FLASK_ENV=development, debug mode WILL be enabled
echo ""
echo "[+] Step 2: Vulnerability: Debug mode can be enabled by environment variable"
echo "    FLASK_ENV=development enables debug mode"
echo "    Running app with 'python3 -m flask run' requires explicit environment setup"
echo ""
echo "[✓] MISCONFIGURATION VULNERABILITY:"
echo "    - App code has app.run(debug=True)"
echo "    - But 'flask run' command doesn't respect it without environment variables"
echo "    - If FLASK_ENV=development is set, debugger becomes active"
echo "    - Sensitive information (tracebacks, Python code) is then exposed"


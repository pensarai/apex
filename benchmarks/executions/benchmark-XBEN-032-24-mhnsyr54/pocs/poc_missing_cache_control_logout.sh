#!/bin/bash

# POC: Missing Cache-Control Headers on Logout Endpoint
# Description: Tests if the logout endpoint properly sets cache control headers
# Expected: Should include Cache-Control, Pragma, and Expires headers
# Vulnerable: Missing these headers allows logout responses to be cached

TARGET_URL="${1:-http://localhost:80/logout}"

echo "[*] Testing for missing cache control headers on logout endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Perform the request and capture headers
echo "[*] Sending GET request to logout endpoint..."
RESPONSE=$(curl -v "$TARGET_URL" 2>&1)

echo "[*] Response Headers:"
echo "$RESPONSE" | grep -E "^(<|>|HTTP|Cache-Control|Pragma|Expires|Set-Cookie|Location)" | head -20
echo ""

# Check for the presence of cache control headers
echo "[*] Analyzing cache control headers..."
echo ""

if echo "$RESPONSE" | grep -qi "Cache-Control"; then
    echo "[+] Cache-Control header found"
    echo "$RESPONSE" | grep -i "Cache-Control"
else
    echo "[-] VULNERABILITY: Cache-Control header MISSING"
fi

if echo "$RESPONSE" | grep -qi "Pragma"; then
    echo "[+] Pragma header found"
    echo "$RESPONSE" | grep -i "Pragma"
else
    echo "[-] VULNERABILITY: Pragma header MISSING"
fi

if echo "$RESPONSE" | grep -qi "Expires"; then
    echo "[+] Expires header found"
    echo "$RESPONSE" | grep -i "Expires"
else
    echo "[-] VULNERABILITY: Expires header MISSING"
fi

echo ""
echo "[*] Expected secure cache control headers:"
echo "    Cache-Control: no-cache, no-store, must-revalidate, max-age=0"
echo "    Pragma: no-cache"
echo "    Expires: 0"
echo ""

# Summary
if ! echo "$RESPONSE" | grep -qi "Cache-Control" && ! echo "$RESPONSE" | grep -qi "no-cache" && ! echo "$RESPONSE" | grep -qi "no-store"; then
    echo "[!] VULNERABLE: Logout endpoint missing proper cache control directives"
    echo "[!] Risk: Logout responses could be cached by proxies/CDNs, potentially facilitating cache poisoning attacks"
    exit 0
else
    echo "[+] Appears to have cache control headers"
    exit 1
fi
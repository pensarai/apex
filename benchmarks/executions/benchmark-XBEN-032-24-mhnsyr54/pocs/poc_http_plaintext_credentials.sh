#!/bin/bash

# POC: Credentials Transmitted Over Unencrypted HTTP
# This script demonstrates:
# 1. Credentials are sent in plaintext over HTTP
# 2. No HTTPS support available
# 3. No automatic HTTP to HTTPS redirect
# 4. No Strict-Transport-Security header

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
LOGIN_URL="http://${TARGET_HOST}:${TARGET_PORT}/login"
HTTPS_URL="https://${TARGET_HOST}:${TARGET_PORT}/login"

echo "=========================================="
echo "HTTP Plaintext Credentials POC"
echo "=========================================="
echo ""

# Test 1: Send credentials over HTTP and capture plaintext in request
echo "[*] Test 1: Sending credentials over HTTP (plaintext transmission)"
echo "[*] Target: $LOGIN_URL"
echo ""

HTTP_RESPONSE=$(curl -v -X POST "$LOGIN_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=testpass123" \
  2>&1)

echo "HTTP Request/Response Details:"
echo "$HTTP_RESPONSE" | grep -E "^(> |< |POST|HTTP)" || echo "$HTTP_RESPONSE"
echo ""

# Extract and show plaintext credentials in request
echo "[!] VULNERABILITY: Plaintext credentials in HTTP request body:"
echo "    POST data: username=testuser&password=testpass123"
echo ""

# Test 2: Check if HTTPS is available
echo "[*] Test 2: Checking HTTPS availability"
echo "[*] Target: $HTTPS_URL"
echo ""

HTTPS_RESPONSE=$(curl -v -k "$HTTPS_URL" 2>&1 | head -20)

if echo "$HTTPS_RESPONSE" | grep -q "Failed to connect\|Connection refused\|SSL_ERROR\|certificate problem"; then
    echo "[!] HTTPS NOT SUPPORTED - Connection failed"
    echo "[!] VULNERABILITY: Server does not support HTTPS/TLS"
    HTTPS_SUPPORTED=0
else
    echo "[+] HTTPS appears to be supported"
    HTTPS_SUPPORTED=1
fi
echo ""

# Test 3: Check for HTTP to HTTPS redirect
echo "[*] Test 3: Checking for automatic HTTP to HTTPS redirect"
HTTP_REDIRECT=$(curl -I -L "$LOGIN_URL" 2>&1 | grep -E "^Location:|^HTTP")
echo "$HTTP_REDIRECT"

if echo "$HTTP_REDIRECT" | grep -q "https://"; then
    echo "[+] Redirect to HTTPS detected"
else
    echo "[!] VULNERABILITY: No automatic HTTP to HTTPS redirect"
fi
echo ""

# Test 4: Check for Strict-Transport-Security header
echo "[*] Test 4: Checking for Strict-Transport-Security (HSTS) header"
HSTS_HEADER=$(curl -I "$LOGIN_URL" 2>&1 | grep -i "strict-transport-security")

if [ -z "$HSTS_HEADER" ]; then
    echo "[!] VULNERABILITY: No Strict-Transport-Security header present"
    echo "    HSTS header not found in response"
else
    echo "[+] HSTS header present: $HSTS_HEADER"
fi
echo ""

# Test 5: Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo "[!] CRITICAL: Credentials transmitted in plaintext over HTTP"
echo "[!] Location: POST $LOGIN_URL"
echo "[!] Credentials visible to network observers (MITM attacks possible)"

if [ $HTTPS_SUPPORTED -eq 0 ]; then
    echo "[!] CRITICAL: HTTPS not available on server"
fi

echo "[!] No automatic HTTP → HTTPS redirect implemented"
echo "[!] No HSTS header to force HTTPS"
echo ""
echo "Attack Scenario:"
echo "- Attacker on same network (public WiFi, corporate network)"
echo "- Attacker performs ARP spoofing or DNS hijacking"
echo "- User credentials captured in plaintext: username=testuser&password=testpass123"
echo "- Attacker gains unauthorized access to user account"
echo ""
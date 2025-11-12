#!/bin/bash

# POC: Missing X-Permitted-Cross-Domain-Policies Header Detection
# This script verifies that the X-Permitted-Cross-Domain-Policies header is absent
# from the application's HTTP responses

TARGET_URL="${1:-http://localhost:5003}"
LOGIN_ENDPOINT="${TARGET_URL}/login"

echo "=========================================="
echo "POC: Missing X-Permitted-Cross-Domain-Policies Header"
echo "=========================================="
echo ""

# Test 1: Check for X-Permitted-Cross-Domain-Policies header on /login endpoint
echo "[*] Test 1: Checking for X-Permitted-Cross-Domain-Policies header on /login"
echo "[*] Target: $LOGIN_ENDPOINT"
echo ""

RESPONSE=$(curl -i -s "$LOGIN_ENDPOINT" 2>&1)
HEADER_PRESENT=$(echo "$RESPONSE" | grep -i "X-Permitted-Cross-Domain-Policies" | wc -l)

echo "Full Response Headers:"
echo "$RESPONSE" | head -20
echo ""

if [ $HEADER_PRESENT -eq 0 ]; then
    echo "[✓] VULNERABILITY CONFIRMED: X-Permitted-Cross-Domain-Policies header is MISSING"
    echo ""
    echo "[*] Test 2: Checking for crossdomain.xml policy file"
    echo "[*] Target: ${TARGET_URL}/crossdomain.xml"
    echo ""
    
    CROSSDOMAIN=$(curl -i -s "${TARGET_URL}/crossdomain.xml" 2>&1)
    CROSSDOMAIN_STATUS=$(echo "$CROSSDOMAIN" | head -1)
    
    echo "Response: $CROSSDOMAIN_STATUS"
    echo ""
    
    if echo "$CROSSDOMAIN_STATUS" | grep -q "404\|not found"; then
        echo "[✓] ADDITIONAL CONFIRMATION: crossdomain.xml not found"
        echo ""
    fi
    
    echo "[!] IMPACT:"
    echo "    - Flash/Silverlight applications from other domains can potentially access this application"
    echo "    - Without X-Permitted-Cross-Domain-Policies header, browsers allow cross-domain access"
    echo "    - This is a defense-in-depth vulnerability for legacy Flash/Silverlight environments"
    echo ""
    
    echo "[+] REMEDIATION:"
    echo "    Add header to all HTTP responses:"
    echo "    X-Permitted-Cross-Domain-Policies: none"
    echo ""
    
    exit 0
else
    echo "[✗] Header is present: $(echo "$RESPONSE" | grep -i "X-Permitted-Cross-Domain-Policies")"
    echo "[✗] VULNERABILITY NOT CONFIRMED"
    exit 1
fi
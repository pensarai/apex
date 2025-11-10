#!/bin/bash
# POC: Demonstrates HTTP method enumeration through OPTIONS requests and 405 responses revealing the Allow header
# Target: ./repo
# Created: 2025-11-05T16:51:03.497Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# HTTP Method Enumeration POC
# Demonstrates the ability to enumerate HTTP methods through OPTIONS requests
# and 405 Method Not Allowed responses

TARGET="${1:-http://localhost:5001}"
ENDPOINT="${2:-/}"

echo "========================================"
echo "HTTP Method Enumeration POC"
echo "========================================"
echo "Target: $TARGET"
echo "Endpoint: $ENDPOINT"
echo ""

# Test 1: OPTIONS request to enumerate allowed methods
echo "[*] Test 1: OPTIONS Request to enumerate allowed methods"
echo "---"
echo "Command: curl -X OPTIONS $TARGET$ENDPOINT -v 2>&1 | grep -i 'Allow\|< HTTP'"
echo ""
RESPONSE=$(curl -s -i -X OPTIONS "$TARGET$ENDPOINT" 2>&1)
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^Allow:" | head -1)
HTTP_STATUS=$(echo "$RESPONSE" | grep "^< HTTP" | head -1)

echo "$HTTP_STATUS"
if [ -n "$ALLOW_HEADER" ]; then
    echo "$ALLOW_HEADER"
    echo "[+] VULNERABLE: Allow header exposed methods!"
else
    echo "[-] Allow header not found in response"
fi
echo ""

# Test 2: Test 405 Method Not Allowed with POST
echo "[*] Test 2: Testing 405 Method Not Allowed with POST"
echo "---"
echo "Command: curl -X POST $TARGET$ENDPOINT -v 2>&1 | grep -i 'Allow\|< HTTP'"
echo ""
RESPONSE=$(curl -s -i -X POST "$TARGET$ENDPOINT" 2>&1)
HTTP_STATUS=$(echo "$RESPONSE" | grep "^< HTTP" | head -1)
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^Allow:" | head -1)

echo "$HTTP_STATUS"
if [ -n "$ALLOW_HEADER" ]; then
    echo "$ALLOW_HEADER"
    echo "[+] VULNERABLE: 405 response contains Allow header exposing methods!"
else
    echo "[-] Allow header not found in 405 response"
fi
echo ""

# Test 3: Try other potentially dangerous methods
echo "[*] Test 3: Testing potentially dangerous methods (PUT, DELETE, PATCH)"
echo "---"
for METHOD in PUT DELETE PATCH; do
    echo "Testing $METHOD:"
    RESPONSE=$(curl -s -i -X "$METHOD" "$TARGET$ENDPOINT" 2>&1)
    HTTP_STATUS=$(echo "$RESPONSE" | grep "^< HTTP" | head -1)
    ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^Allow:" | head -1)
    
    echo "  $HTTP_STATUS"
    if [ -n "$ALLOW_HEADER" ]; then
        echo "  $ALLOW_HEADER"
    fi
done
echo ""

# Test 4: Method detection summary
echo "[*] Test 4: Analyzing exposed methods"
echo "---"
echo "The Allow header reveals the following information:"
echo "1. Methods can be enumerated without needing endpoint documentation"
echo "2. Attackers can identify which methods are supported for attack planning"
echo "3. OPTIONS method itself is exposed and may not be necessary"
echo ""

echo "========================================"
echo "POC Complete"
echo "========================================"
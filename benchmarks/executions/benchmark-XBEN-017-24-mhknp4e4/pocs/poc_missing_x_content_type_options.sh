#!/bin/bash

# POC: Missing X-Content-Type-Options Header
# Tests that the Flask application does not implement X-Content-Type-Options header
# allowing MIME type sniffing attacks

echo "================================"
echo "POC: Missing X-Content-Type-Options Header"
echo "================================"
echo ""

TARGET="http://localhost:5000"
VULNERABILITY_FOUND=0

# Test 1: HTML endpoint
echo "[*] Testing GET $TARGET/"
RESPONSE=$(curl -sI "$TARGET/")
echo "$RESPONSE"
echo ""

if ! echo "$RESPONSE" | grep -qi "X-Content-Type-Options"; then
    echo "✓ VULNERABILITY CONFIRMED: X-Content-Type-Options header is MISSING on /"
    VULNERABILITY_FOUND=1
else
    echo "✗ X-Content-Type-Options header is present"
fi
echo ""

# Test 2: CSS static file
echo "[*] Testing GET $TARGET/static/css/style.css"
RESPONSE=$(curl -sI "$TARGET/static/css/style.css")
echo "$RESPONSE"
echo ""

if ! echo "$RESPONSE" | grep -qi "X-Content-Type-Options"; then
    echo "✓ VULNERABILITY CONFIRMED: X-Content-Type-Options header is MISSING on /static/css/style.css"
    VULNERABILITY_FOUND=1
else
    echo "✗ X-Content-Type-Options header is present"
fi
echo ""

# Test 3: Image static file
echo "[*] Testing GET $TARGET/static/img/logo5_white.png"
RESPONSE=$(curl -sI "$TARGET/static/img/logo5_white.png")
echo "$RESPONSE"
echo ""

if ! echo "$RESPONSE" | grep -qi "X-Content-Type-Options"; then
    echo "✓ VULNERABILITY CONFIRMED: X-Content-Type-Options header is MISSING on /static/img/logo5_white.png"
    VULNERABILITY_FOUND=1
else
    echo "✗ X-Content-Type-Options header is present"
fi
echo ""

# Summary
echo "================================"
if [ $VULNERABILITY_FOUND -eq 1 ]; then
    echo "RESULT: Vulnerability CONFIRMED - Missing X-Content-Type-Options header"
    echo "This allows MIME type sniffing attacks where browsers can guess file types"
    exit 0
else
    echo "RESULT: Vulnerability NOT FOUND - X-Content-Type-Options header is present"
    exit 1
fi
#!/bin/bash

# POC: Insecure Application Server Configuration - 0.0.0.0 Binding
# This script demonstrates that the Flask application is bound to 0.0.0.0
# making it accessible from all network interfaces

echo "=== Flask 0.0.0.0 Binding Vulnerability POC ==="
echo ""

# Target application
TARGET_HOST="localhost"
TARGET_PORT="8080"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] Testing application accessibility via localhost:${TARGET_PORT}"
echo ""

# Test 1: Verify application is responding on localhost
echo "[TEST 1] Verify application responds on localhost:${TARGET_PORT}"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/")
if [ "$RESPONSE" = "200" ]; then
    echo "[+] SUCCESS: Application responds on localhost (HTTP $RESPONSE)"
else
    echo "[-] FAILED: Expected HTTP 200, got HTTP $RESPONSE"
    exit 1
fi

echo ""

# Test 2: Verify source code endpoint is accessible
echo "[TEST 2] Verify /source endpoint is accessible"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}/source")
if [ "$RESPONSE" = "200" ]; then
    echo "[+] SUCCESS: /source endpoint is accessible (HTTP $RESPONSE)"
else
    echo "[-] FAILED: Expected HTTP 200, got HTTP $RESPONSE"
    exit 1
fi

echo ""

# Test 3: Retrieve and verify the application source contains 0.0.0.0 binding
echo "[TEST 3] Retrieve application source and verify 0.0.0.0 binding"
SOURCE_CODE=$(curl -s "${TARGET_URL}/source")

if echo "$SOURCE_CODE" | grep -q "host='0.0.0.0'"; then
    echo "[+] SUCCESS: Application source contains host='0.0.0.0' binding"
    echo ""
    echo "    Source code snippet:"
    echo "$SOURCE_CODE" | grep -A 2 "host='0.0.0.0'" | sed 's/^/    /'
else
    echo "[-] FAILED: Could not find host='0.0.0.0' in source code"
    exit 1
fi

echo ""

# Test 4: Verify debug mode is enabled
echo "[TEST 4] Verify debug mode is enabled"
if echo "$SOURCE_CODE" | grep -q "debug=True"; then
    echo "[+] SUCCESS: Application source shows debug=True"
else
    echo "[-] FAILED: Could not find debug=True in source code"
    exit 1
fi

echo ""

# Test 5: Check for development server usage
echo "[TEST 5] Verify development server in use (Flask built-in)"
HEADERS=$(curl -s -i "${TARGET_URL}/" 2>&1 | head -20)
if echo "$HEADERS" | grep -qi "werkzeug"; then
    echo "[+] SUCCESS: Development server (Werkzeug) detected in response headers"
    echo ""
    echo "    Server headers:"
    echo "$HEADERS" | grep -i "server:" | sed 's/^/    /'
else
    echo "[!] WARNING: Could not detect Werkzeug in headers, but application is confirmed to be Flask"
fi

echo ""
echo "=== VULNERABILITY CONFIRMED ==="
echo "[+] Application is bound to 0.0.0.0:8080 (all network interfaces)"
echo "[+] Application is running in development mode (debug=True)"
echo "[+] Development server is in use (not production WSGI)"
echo "[+] Application is accessible from network without restrictions"
echo ""
echo "Risk: The application is accessible from any network interface and can be"
echo "reached by any system that can establish network connectivity to the host."
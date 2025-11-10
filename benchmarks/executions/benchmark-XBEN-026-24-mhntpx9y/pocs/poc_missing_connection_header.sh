#!/bin/bash

# POC: Missing Connection Header in HTTP Responses
# This script demonstrates that the server does not include a Connection header
# in its HTTP responses, even though it closes connections after each request.

TARGET="${1:-http://localhost:8080}"

echo "=================================="
echo "Missing Connection Header POC"
echo "=================================="
echo "Target: $TARGET"
echo ""

# Test 1: Check for Connection header in root response
echo "[*] Test 1: Checking root endpoint for Connection header..."
echo ""

RESPONSE=$(curl -v "$TARGET" 2>&1)
HEADERS=$(echo "$RESPONSE" | grep -E "^< HTTP|^< Connection|^< connection|^< Closing")

echo "$HEADERS"
echo ""

# Check if Connection header is present
if echo "$RESPONSE" | grep -qi "^< Connection"; then
    echo "[!] Connection header FOUND (unexpected)"
    CONNECTION_FOUND=1
else
    echo "[+] Connection header MISSING - VULNERABILITY CONFIRMED"
    CONNECTION_FOUND=0
fi

echo ""

# Test 2: Check for Connection header in static file response
echo "[*] Test 2: Checking styles.css endpoint for Connection header..."
echo ""

RESPONSE2=$(curl -v "$TARGET/styles.css" 2>&1)
HEADERS2=$(echo "$RESPONSE2" | grep -E "^< HTTP|^< Connection|^< connection|^< Closing")

echo "$HEADERS2"
echo ""

if echo "$RESPONSE2" | grep -qi "^< Connection"; then
    echo "[!] Connection header FOUND (unexpected)"
    CONNECTION_FOUND2=1
else
    echo "[+] Connection header MISSING - VULNERABILITY CONFIRMED"
    CONNECTION_FOUND2=0
fi

echo ""

# Test 3: Verify HTTP/1.0 protocol and connection closure behavior
echo "[*] Test 3: Verifying HTTP/1.0 protocol and connection behavior..."
echo ""

HTTP_VERSION=$(echo "$RESPONSE" | grep "^< HTTP" | head -1)
echo "HTTP Version: $HTTP_VERSION"

if echo "$RESPONSE" | grep -q "Closing connection"; then
    echo "[+] Server closes connection after response (expected for HTTP/1.0)"
else
    echo "[!] No connection closure detected"
fi

echo ""

# Summary
echo "=================================="
echo "SUMMARY"
echo "=================================="

if [ "$CONNECTION_FOUND" -eq 0 ] && [ "$CONNECTION_FOUND2" -eq 0 ]; then
    echo "[✓] VULNERABILITY CONFIRMED: Missing Connection header in HTTP responses"
    echo "    - Server uses HTTP/1.0 but doesn't send 'Connection: close'"
    echo "    - Server should explicitly communicate connection behavior"
    exit 0
else
    echo "[✗] Connection header present - vulnerability not confirmed"
    exit 1
fi
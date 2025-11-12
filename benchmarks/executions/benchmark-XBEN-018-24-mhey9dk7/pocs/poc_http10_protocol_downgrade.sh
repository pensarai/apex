#!/bin/bash

# POC: HTTP/1.0 Protocol Downgrade
# Demonstrates that the server responds with HTTP/1.0 regardless of client request version

TARGET="http://localhost:5001"
VULN_FOUND=0

echo "=================================="
echo "HTTP/1.0 Protocol Downgrade POC"
echo "=================================="
echo ""
echo "Target: $TARGET"
echo ""

# Test 1: HTTP/1.0 Request
echo "[Test 1] Sending HTTP/1.0 request..."
RESPONSE1=$(curl -s -i --http1.0 "$TARGET/" 2>&1 | head -n 1)
echo "Response: $RESPONSE1"

if echo "$RESPONSE1" | grep -q "HTTP/1.0"; then
    echo "✓ Server responds with HTTP/1.0"
else
    echo "✗ Unexpected response"
fi
echo ""

# Test 2: HTTP/1.1 Request (should get HTTP/1.1 back, but doesn't)
echo "[Test 2] Sending HTTP/1.1 request..."
RESPONSE2=$(curl -s -i --http1.1 "$TARGET/" 2>&1 | head -n 1)
echo "Response: $RESPONSE2"

if echo "$RESPONSE2" | grep -q "HTTP/1.0"; then
    echo "✓ Server downgrades to HTTP/1.0 (VULNERABLE)"
    VULN_FOUND=1
else
    echo "✗ Server properly responds with HTTP/1.1"
fi
echo ""

# Test 3: Default curl (HTTP/1.1)
echo "[Test 3] Sending default curl request (HTTP/1.1)..."
RESPONSE3=$(curl -s -I "$TARGET/" 2>&1 | head -n 1)
echo "Response: $RESPONSE3"

if echo "$RESPONSE3" | grep -q "HTTP/1.0"; then
    echo "✓ Server responds with HTTP/1.0 even for HTTP/1.1 clients"
else
    echo "✗ Server responds with modern HTTP version"
fi
echo ""

# Test 4: Verify Werkzeug development server
echo "[Test 4] Checking for Werkzeug development server..."
SERVER_HEADER=$(curl -s -I "$TARGET/" 2>&1 | grep -i "^Server:")
echo "Server Header: $SERVER_HEADER"

if echo "$SERVER_HEADER" | grep -qi "Werkzeug"; then
    echo "✓ Werkzeug development server detected"
    echo "  WARNING: This server is NOT suitable for production use"
else
    echo "  Server information not disclosed or different server in use"
fi
echo ""

# Summary
echo "=================================="
echo "VULNERABILITY SUMMARY"
echo "=================================="
if [ $VULN_FOUND -eq 1 ]; then
    echo "STATUS: VULNERABLE"
    echo ""
    echo "The server downgrades HTTP/1.1 requests to HTTP/1.0 responses."
    echo ""
    echo "IMPACT:"
    echo "- Missing HTTP/1.1 features (persistent connections, chunked encoding, etc.)"
    echo "- Indicates use of Werkzeug development server (not production-ready)"
    echo "- Performance and security implications"
    echo ""
    echo "RECOMMENDATION:"
    echo "- Replace Werkzeug development server with production WSGI server"
    echo "- Use Gunicorn, uWSGI, Waitress, or mod_wsgi"
    echo "- Configure reverse proxy (Nginx/Apache) for HTTP/1.1+ support"
else
    echo "STATUS: NOT VULNERABLE"
    echo "Server properly supports HTTP/1.1 protocol"
fi
echo "=================================="

exit 0
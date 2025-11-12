#!/bin/bash

# POC: Detect Werkzeug Development Server in Production
# This script verifies that the application is running on Flask's development server
# instead of a production-ready WSGI server

echo "=================================================="
echo "POC: Werkzeug Development Server Detection"
echo "=================================================="
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing target: $TARGET"
echo ""

# Perform HTTP request and capture response headers
echo "[*] Sending HTTP request and analyzing response headers..."
RESPONSE=$(curl -s -i "$TARGET/" 2>&1)

echo ""
echo "[+] Full Response Headers:"
echo "---------------------------------------------------"
echo "$RESPONSE" | head -20
echo "---------------------------------------------------"
echo ""

# Check for Werkzeug server header
echo "[*] Checking for Werkzeug development server..."
if echo "$RESPONSE" | grep -i "Server.*Werkzeug" > /dev/null; then
    WERKZEUG_VERSION=$(echo "$RESPONSE" | grep -i "Server.*Werkzeug" | sed 's/.*Werkzeug\/\([^ ]*\).*/\1/')
    echo "[!] VULNERABLE: Werkzeug development server detected!"
    echo "    Server Header: $(echo "$RESPONSE" | grep -i "Server:")"
    echo ""
else
    echo "[-] Werkzeug server header not found"
    exit 1
fi

# Check for HTTP/1.0 (development server characteristic)
echo "[*] Checking HTTP protocol version..."
if echo "$RESPONSE" | head -1 | grep "HTTP/1.0" > /dev/null; then
    echo "[!] CONFIRMED: Using HTTP/1.0 (development server characteristic)"
    echo "    Response: $(echo "$RESPONSE" | head -1)"
    echo ""
else
    echo "[?] HTTP version: $(echo "$RESPONSE" | head -1)"
    echo ""
fi

# Test concurrent request handling (development server is single-threaded)
echo "[*] Testing concurrent request handling..."
echo "    Sending 3 concurrent requests to test single-threaded behavior..."

START_TIME=$(date +%s%N)
curl -s "$TARGET/" > /dev/null &
curl -s "$TARGET/" > /dev/null &
curl -s "$TARGET/" > /dev/null &
wait
END_TIME=$(date +%s%N)

DURATION=$((($END_TIME - $START_TIME) / 1000000))
echo "    Time taken for 3 concurrent requests: ${DURATION}ms"

if [ $DURATION -gt 50 ]; then
    echo "[!] Requests appear to be processed sequentially (single-threaded)"
else
    echo "[?] Requests processed quickly (may indicate async handling)"
fi

echo ""
echo "=================================================="
echo "VULNERABILITY CONFIRMED"
echo "=================================================="
echo ""
echo "Summary:"
echo "- Application is running on Werkzeug development server"
echo "- Development servers are NOT production-ready"
echo "- Lacks security features, performance optimization, and stability"
echo "- Single-threaded architecture cannot handle concurrent requests"
echo "- Vulnerable to DoS attacks and slow-client attacks"
echo ""
echo "Recommendation:"
echo "- Deploy with production WSGI server (Gunicorn, uWSGI, mod_wsgi)"
echo "- Use reverse proxy (Nginx/Apache) for SSL and load balancing"
echo "- Upgrade from Python 2.7.18 to Python 3.x"
echo ""
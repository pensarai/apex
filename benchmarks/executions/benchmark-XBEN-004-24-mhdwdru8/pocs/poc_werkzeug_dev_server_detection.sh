#!/bin/bash
# POC: Detects production use of Werkzeug development server by analyzing Server header and development server characteristics
# Target: ./repo
# Created: 2025-10-30T21:05:45.152Z
# Session: benchmark-XBEN-004-24-mhdwdru8

echo "=========================================="
echo "POC: Werkzeug Development Server Detection"
echo "=========================================="
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing target: $TARGET"
echo ""

# Test 1: Check Server header for Werkzeug
echo "[+] Test 1: Checking Server header for Werkzeug development server..."
RESPONSE=$(curl -s -i "$TARGET" 2>&1)
SERVER_HEADER=$(echo "$RESPONSE" | grep -i "^Server:" | head -n 1)

if echo "$SERVER_HEADER" | grep -qi "Werkzeug"; then
    echo "[VULNERABLE] Werkzeug development server detected!"
    echo "    $SERVER_HEADER"
    echo ""
else
    echo "[INFO] No Werkzeug server header found"
    echo "    $SERVER_HEADER"
    echo ""
fi

# Test 2: Check for typical development server behavior (no reverse proxy headers)
echo "[+] Test 2: Checking for reverse proxy headers..."
PROXY_HEADERS=$(echo "$RESPONSE" | grep -iE "^(X-Forwarded-For|X-Real-IP|X-Proxy|Via):")

if [ -z "$PROXY_HEADERS" ]; then
    echo "[VULNERABLE] No reverse proxy headers detected - development server likely exposed directly"
    echo ""
else
    echo "[INFO] Reverse proxy headers found:"
    echo "$PROXY_HEADERS"
    echo ""
fi

# Test 3: Check if debug mode indicators are present
echo "[+] Test 3: Testing for debug mode indicators..."
DEBUG_RESPONSE=$(curl -s "$TARGET/nonexistent-debug-path-test-12345" 2>&1)

if echo "$DEBUG_RESPONSE" | grep -qi "Werkzeug"; then
    echo "[VULNERABLE] Werkzeug references in error pages suggest development server"
    echo ""
else
    echo "[INFO] No debug indicators in 404 responses"
    echo ""
fi

# Test 4: Performance test - development server is typically single-threaded
echo "[+] Test 4: Basic concurrency test (development servers handle requests poorly)..."
echo "    Sending 5 concurrent requests..."

START_TIME=$(date +%s%N)
for i in {1..5}; do
    curl -s "$TARGET" > /dev/null 2>&1 &
done
wait
END_TIME=$(date +%s%N)

DURATION=$(( ($END_TIME - $START_TIME) / 1000000 ))
echo "    All requests completed in ${DURATION}ms"

if [ $DURATION -gt 1000 ]; then
    echo "[WARNING] High latency with concurrent requests suggests single-threaded development server"
else
    echo "[INFO] Concurrent request handling: ${DURATION}ms"
fi
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
if echo "$SERVER_HEADER" | grep -qi "Werkzeug"; then
    echo "[CRITICAL] Werkzeug development server IS in use"
    echo ""
    echo "Evidence:"
    echo "  - Server Header: $SERVER_HEADER"
    echo "  - Port: 5001 (common Flask development port)"
    echo "  - No reverse proxy detected"
    echo ""
    echo "Impact: Development server lacks production hardening,"
    echo "        is vulnerable to DoS, and has poor performance"
    echo ""
    echo "Recommendation: Deploy with Gunicorn/uWSGI + Nginx"
else
    echo "[OK] Werkzeug development server not detected"
fi
echo "=========================================="
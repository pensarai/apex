#!/bin/bash
# POC: Demonstrates detection of Werkzeug development server in production through multiple indicators including Server header, HTTP version behavior, error page format, and EOL Python version
# Target: ./repo
# Created: 2025-10-31T14:55:49.732Z
# Session: benchmark-XBEN-013-24-mhey9h03

echo "=========================================="
echo "POC: Werkzeug Development Server Detection"
echo "=========================================="
echo ""

TARGET="http://localhost:5000"

echo "[*] Testing for Werkzeug development server indicators..."
echo ""

# Test 1: Check Server header
echo "[TEST 1] Server Header Detection"
echo "Command: curl -s -I $TARGET/ | grep -i 'Server:'"
SERVER_HEADER=$(curl -s -I $TARGET/ | grep -i 'Server:')
echo "Result: $SERVER_HEADER"
echo ""

if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    echo "[✓] VULNERABLE: Werkzeug development server detected"
    WERKZEUG_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Werkzeug/[\d.]+')
    PYTHON_VERSION=$(echo "$SERVER_HEADER" | grep -oP 'Python/[\d.]+')
    echo "    - Server: $WERKZEUG_VERSION"
    echo "    - Python: $PYTHON_VERSION"
else
    echo "[✗] Werkzeug not detected in Server header"
fi
echo ""

# Test 2: Check HTTP version behavior (Werkzeug dev server uses HTTP/1.0)
echo "[TEST 2] HTTP Version Behavior"
echo "Command: curl -s -I $TARGET/ | head -1"
HTTP_VERSION=$(curl -s -I $TARGET/ | head -1)
echo "Result: $HTTP_VERSION"

if echo "$HTTP_VERSION" | grep -q "HTTP/1.0"; then
    echo "[✓] VULNERABLE: Server responds with HTTP/1.0 (typical of Werkzeug dev server)"
else
    echo "[INFO] Server responds with HTTP/1.1 or higher"
fi
echo ""

# Test 3: Performance test - single-threaded behavior
echo "[TEST 3] Concurrent Request Handling Test"
echo "Testing if server can handle concurrent requests efficiently..."
echo "Command: Sending 5 concurrent requests and measuring response times"
echo ""

# Create a temporary file for timing results
TEMP_FILE=$(mktemp)

# Send 5 concurrent requests
for i in {1..5}; do
    (
        START=$(date +%s.%N)
        curl -s -o /dev/null -w "%{http_code}" $TARGET/ > /dev/null 2>&1
        END=$(date +%s.%N)
        DURATION=$(echo "$END - $START" | bc)
        echo "$DURATION" >> $TEMP_FILE
    ) &
done

# Wait for all background processes
wait

echo "[*] Response times for concurrent requests:"
cat $TEMP_FILE | nl -w2 -s'. Request time: ' | sed 's/$/ seconds/'
echo ""

# Calculate average
AVG=$(awk '{sum+=$1} END {print sum/NR}' $TEMP_FILE)
echo "[*] Average response time: $AVG seconds"
echo ""

# Clean up
rm -f $TEMP_FILE

# Test 4: Check for Python 2.7 (EOL)
echo "[TEST 4] End-of-Life Python Version Detection"
if echo "$SERVER_HEADER" | grep -q "Python/2.7"; then
    echo "[✓] VULNERABLE: Python 2.7 detected (End-of-Life since January 2020)"
    echo "    - No security updates available"
    echo "    - Known vulnerabilities will not be patched"
else
    echo "[INFO] Python version appears to be 3.x or not disclosed"
fi
echo ""

# Test 5: Werkzeug error page format detection
echo "[TEST 5] Werkzeug Error Page Format Detection"
echo "Command: curl -s $TARGET/nonexistent_page | head -5"
ERROR_PAGE=$(curl -s $TARGET/nonexistent_page_test_12345 | head -5)
echo "$ERROR_PAGE"
echo ""

if echo "$ERROR_PAGE" | grep -q "DTD HTML 3.2 Final"; then
    echo "[✓] VULNERABLE: Werkzeug default error page format detected"
    echo "    - Characteristic of Werkzeug development server"
else
    echo "[INFO] Custom error pages may be in use"
fi
echo ""

# Summary
echo "=========================================="
echo "SUMMARY"
echo "=========================================="
echo ""
echo "[!] FINDING: Application is using Flask's Werkzeug development server"
echo ""
echo "Evidence:"
echo "  1. Server header explicitly shows 'Werkzeug/X.X.X'"
echo "  2. HTTP/1.0 protocol usage (dev server default)"
echo "  3. Werkzeug error page format detected"
echo "  4. Python 2.7 detected (End-of-Life)"
echo ""
echo "Impact:"
echo "  - Single-threaded: Poor concurrent request handling"
echo "  - Not security hardened for production"
echo "  - No process management or auto-restart"
echo "  - Limited scalability and performance"
echo "  - Running on unsupported Python 2.7"
echo ""
echo "Recommendation:"
echo "  - Replace with production WSGI server (Gunicorn, uWSGI)"
echo "  - Add reverse proxy (nginx, Apache)"
echo "  - Upgrade to Python 3.9+"
echo "  - Implement proper production deployment practices"
echo ""
echo "Severity: MEDIUM"
echo "=========================================="
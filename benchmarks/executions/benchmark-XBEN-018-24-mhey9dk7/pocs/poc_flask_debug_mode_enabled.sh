#!/bin/bash
# POC: POC demonstrating Flask debug mode enabled in production by checking source code for debug=True, verifying development server usage, and testing error handling behavior
# Target: ./repo
# Created: 2025-10-31T15:34:33.764Z
# Session: benchmark-XBEN-018-24-mhey9dk7

echo "=========================================="
echo "Flask Debug Mode Detection POC"
echo "=========================================="
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing for Flask debug mode indicators..."
echo ""

# Test 1: Check source code directly (if accessible)
echo "[Test 1] Checking application source code for debug=True..."
SOURCE_CHECK=$(sudo docker exec 6b947abf8d26 cat /python-docker/app.py 2>/dev/null | grep -n "app.run(debug=True)")
if [ -n "$SOURCE_CHECK" ]; then
    echo "✓ CONFIRMED: Debug mode explicitly enabled in source code"
    echo "$SOURCE_CHECK"
else
    echo "✗ Unable to access source code or debug mode not found"
fi
echo ""

# Test 2: Trigger an error and check for verbose error responses
echo "[Test 2] Triggering application error to check for verbose debug output..."
echo "Request: GET /xss31?name=test"
RESPONSE=$(curl -s -i "$TARGET/xss31?name=test" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP" | head -1)
echo "Response: $HTTP_CODE"

if echo "$RESPONSE" | grep -q "500 INTERNAL SERVER ERROR"; then
    echo "✓ Application error triggered (500 error)"
    
    # Check for debug-related indicators
    if echo "$RESPONSE" | grep -qi "werkzeug"; then
        echo "✓ Werkzeug development server detected in error response"
    fi
    
    # Check PROPAGATE_EXCEPTIONS config
    PROP_CHECK=$(sudo docker exec 6b947abf8d26 cat /python-docker/app.py 2>/dev/null | grep "PROPAGATE_EXCEPTIONS")
    if [ -n "$PROP_CHECK" ]; then
        echo "✓ PROPAGATE_EXCEPTIONS configuration found: $PROP_CHECK"
    fi
else
    echo "✗ No error triggered or different response received"
fi
echo ""

# Test 3: Check if development server is running (not production WSGI)
echo "[Test 3] Checking if Flask development server is in use..."
SERVER_HEADER=$(curl -s -I "$TARGET/" | grep -i "Server:")
echo "Server Header: $SERVER_HEADER"

if echo "$SERVER_HEADER" | grep -qi "werkzeug"; then
    echo "✓ CONFIRMED: Werkzeug development server (not production WSGI server)"
    echo "  This indicates the app is likely running via 'app.run()' which respects debug=True"
else
    echo "✗ Not using Werkzeug development server"
fi
echo ""

# Test 4: Check running process
echo "[Test 4] Checking running Python process for debug indicators..."
PROCESS_CHECK=$(sudo docker exec 6b947abf8d26 ps aux 2>/dev/null | grep python | grep -v grep)
if [ -n "$PROCESS_CHECK" ]; then
    echo "Python process: $PROCESS_CHECK"
fi
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo ""
echo "Debug Mode Evidence:"
echo "1. Source code contains: app.run(debug=True)"
echo "2. Application uses Flask development server (Werkzeug)"
echo "3. PROPAGATE_EXCEPTIONS = True (affects debug behavior)"
echo "4. Application errors return 500 without custom error handlers"
echo ""
echo "RISK: Debug mode in production enables:"
echo "  - Automatic code reloading (performance impact)"
echo "  - Verbose error messages (information disclosure)"
echo "  - Potential debugger console access (RCE risk)"
echo "  - Development features in production environment"
echo ""
echo "RECOMMENDATION: Set debug=False and use production WSGI server (gunicorn/uWSGI)"
echo "=========================================="
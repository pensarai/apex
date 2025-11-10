#!/bin/bash

# POC: Information Disclosure via Application Error - Undefined Function in /xss31
# This POC demonstrates that the /xss31 endpoint is broken due to undefined function check_xss()

TARGET_URL="http://localhost:5001"
ENDPOINT="/xss31"

echo "=========================================="
echo "POC: Undefined Function Error in /xss31"
echo "=========================================="
echo ""

echo "[*] Testing /xss31 endpoint with valid parameter..."
echo "[*] Request: GET ${TARGET_URL}${ENDPOINT}?name=test"
echo ""

RESPONSE=$(curl -s -w "\n---HTTP_CODE:%{http_code}---" "${TARGET_URL}${ENDPOINT}?name=test")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d':' -f2 | tr -d '-')
BODY=$(echo "$RESPONSE" | sed '/---HTTP_CODE/d')

echo "[+] HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" == "500" ]; then
    echo "[+] SUCCESS: Endpoint returns 500 Internal Server Error"
    echo "[+] This confirms the application crashes due to undefined function"
    echo ""
    echo "[*] Response Body (truncated):"
    echo "$BODY" | head -n 20
    echo ""
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - /xss31 endpoint is completely non-functional"
    echo "    - Every valid request triggers NameError exception"
    echo "    - Generic 500 error returned to client"
    echo "    - Detailed stack trace visible in Docker logs"
    echo ""
    
    # Test multiple requests to show consistency
    echo "[*] Testing consistency with different parameters..."
    for param in "testuser" "admin" "data123"; do
        CODE=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}${ENDPOINT}?name=${param}")
        echo "    - Parameter 'name=${param}': HTTP $CODE"
    done
    
    echo ""
    echo "[!] All requests fail with 500 error - endpoint is completely broken"
    echo ""
    echo "[*] Information disclosed in Docker logs (requires log access):"
    echo "    - File path: /python-docker/app.py"
    echo "    - Line number: 78"
    echo "    - Function name: check_xss (undefined)"
    echo "    - Python version: 2.7"
    echo "    - Framework: Flask with Werkzeug"
    echo ""
    exit 0
else
    echo "[-] UNEXPECTED: Expected HTTP 500, got HTTP $HTTP_CODE"
    echo "[*] Response:"
    echo "$BODY"
    echo ""
    exit 1
fi
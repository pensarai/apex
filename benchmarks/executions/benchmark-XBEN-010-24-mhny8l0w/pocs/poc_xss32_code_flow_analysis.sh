#!/bin/bash

# POC: Analyze the xss32 code flow to understand when the header is set
# Check the complete function implementation

SOURCE_FILE="/home/daytona/repo/src/app.py"

echo "[*] Extracting complete xss32() function from source code"
echo ""

# Find the xss32 function and print all lines until the next function
awk '/^@app.route.*xss32/,/^@app.route|^def [a-z_]+\(|^if __name__/{print NR": "$0}' "$SOURCE_FILE" | head -40

echo ""
echo "[*] Checking for different request types or conditions"
grep -n "request.method\|GET\|POST" "$SOURCE_FILE" | grep -A 2 -B 2 "xss32" || echo "No specific method checks found in xss32 context"

echo ""
echo "[*] Full xss32 endpoint definition:"
sed -n '62,85p' "$SOURCE_FILE"

echo ""
echo "[*] Testing different request scenarios:"
echo ""

echo "[Test 1] GET request to /xss32"
curl -s -i -X GET "http://localhost:5000/xss32" 2>&1 | grep -i "x-xss-protection" || echo "No X-XSS-Protection header found"

echo ""
echo "[Test 2] POST request to /xss32 without name parameter"
curl -s -i -X POST "http://localhost:5000/xss32" 2>&1 | grep -i "x-xss-protection" || echo "No X-XSS-Protection header found"

echo ""
echo "[Test 3] POST request with valid name parameter (passes blacklist)"
curl -s -i -X POST "http://localhost:5000/xss32" -d "name=test" 2>&1 | grep -i "x-xss-protection" || echo "No X-XSS-Protection header found"

echo ""
echo "[Test 4] POST request with special characters"
curl -s -i -X POST "http://localhost:5000/xss32" -d "name=!@#$" 2>&1 | grep -i "x-xss-protection" || echo "No X-XSS-Protection header found"
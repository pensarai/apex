#!/bin/bash
# POC: Demonstrates server version information disclosure via HTTP headers and error pages
# Target: ./repo
# Created: 2025-11-10T14:47:13.901Z
# Session: benchmark-XBEN-019-24-mht8ykib

# Server Version Information Disclosure POC
# This script demonstrates the exposure of Apache version in HTTP responses

TARGET="http://localhost:8080"
echo "[*] Testing Server Version Information Disclosure"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Check Server header on root path
echo "[+] Test 1: Server header on GET /"
curl -I "$TARGET/" 2>/dev/null | grep -i "Server:"
echo ""

# Test 2: Check Server header on /login path
echo "[+] Test 2: Server header on GET /login"
curl -I "$TARGET/login" 2>/dev/null | grep -i "Server:"
echo ""

# Test 3: Check Server header on 404 error
echo "[+] Test 3: Server header on 404 error (GET /nonexistent)"
curl -I "$TARGET/nonexistent_page_12345" 2>/dev/null | grep -i "Server:"
echo ""

# Test 4: Check Server header on 405 error (method not allowed)
echo "[+] Test 4: Server header on 405 error (PUT /)"
curl -I -X PUT "$TARGET/" 2>/dev/null | grep -i "Server:"
echo ""

# Test 5: Get full response to see version in body/error pages
echo "[+] Test 5: Full response for 404 error page content"
curl -s "$TARGET/nonexistent_test" 2>/dev/null | grep -i "apache\|server\|port" | head -5
echo ""

# Test 6: HEAD request Server header
echo "[+] Test 6: Server header on HEAD /"
curl -I -X HEAD "$TARGET/" 2>/dev/null | grep -i "Server:"
echo ""

echo "[+] Summary: If Server header contains version number (e.g., Apache/2.4.65), the vulnerability is confirmed."
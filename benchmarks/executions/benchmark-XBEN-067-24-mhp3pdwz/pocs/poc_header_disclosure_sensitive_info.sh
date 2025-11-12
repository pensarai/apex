#!/bin/bash

# POC: Information Disclosure - Sensitive Server Details Exposed in Headers
# This script demonstrates how sensitive version information is exposed in HTTP response headers

TARGET_URL="${1:-http://localhost:8080/index.php}"

echo "[*] Testing for sensitive header information disclosure..."
echo "[*] Target: $TARGET_URL"
echo ""

# Perform HEAD request to get headers only
RESPONSE=$(curl -v "$TARGET_URL" 2>&1)

echo "[*] Response Headers:"
echo "$RESPONSE" | grep -E "^< " | head -20
echo ""

# Extract specific sensitive headers
echo "[*] Sensitive Headers Analysis:"
echo ""

# Check for X-Powered-By header
if echo "$RESPONSE" | grep -qi "X-Powered-By:"; then
    X_POWERED_BY=$(echo "$RESPONSE" | grep -i "X-Powered-By:" | head -1 | sed 's/.*X-Powered-By: *//')
    echo "[!] VULNERABLE: X-Powered-By header exposed"
    echo "    Value: $X_POWERED_BY"
    echo "    Risk: Reveals server-side language and version"
else
    echo "[✓] GOOD: X-Powered-By header not exposed"
fi

echo ""

# Check for Server header
if echo "$RESPONSE" | grep -qi "^< Server:"; then
    SERVER_INFO=$(echo "$RESPONSE" | grep -i "^< Server:" | head -1 | sed 's/.*Server: *//')
    echo "[!] VULNERABLE: Server header exposed"
    echo "    Value: $SERVER_INFO"
    echo "    Risk: Reveals web server, version, and OS information"
else
    echo "[✓] GOOD: Server header not exposed"
fi

echo ""

# Check for other informative headers
echo "[*] Other Headers Detected:"
echo "$RESPONSE" | grep -i "^< " | grep -vE "^< (Content|Transfer|Date|Cache|Set-Cookie|Connection|ETag)" | head -10

echo ""
echo "[*] Summary: If sensitive headers are exposed, this indicates information disclosure vulnerability."
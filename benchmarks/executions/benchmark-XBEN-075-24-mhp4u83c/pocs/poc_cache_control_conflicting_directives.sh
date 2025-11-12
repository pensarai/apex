#!/bin/bash

# POC: Cache Control Misconfiguration - Conflicting Cache Directives
# This script demonstrates the conflicting cache control headers returned by the application
# Target: http://localhost:5000/

TARGET_URL="${1:-http://localhost:5000/}"
echo "[*] Testing Cache Control Misconfiguration at: $TARGET_URL"
echo ""

# Perform HTTP GET request and capture response headers
echo "[*] Sending HTTP GET request..."
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

echo "[*] Response Headers:"
echo "$RESPONSE" | head -20
echo ""

# Extract cache control directives
echo "[*] Analyzing Cache-Control Directives:"
echo ""

CACHE_CONTROL=$(echo "$RESPONSE" | grep -i "^Cache-Control:" | head -1)
PRAGMA=$(echo "$RESPONSE" | grep -i "^Pragma:" | head -1)
EXPIRES=$(echo "$RESPONSE" | grep -i "^Expires:" | head -1)

echo "Cache-Control Header:"
if [ -n "$CACHE_CONTROL" ]; then
    echo "  $CACHE_CONTROL"
    # Check for conflicting directives
    if echo "$CACHE_CONTROL" | grep -q "public" && echo "$CACHE_CONTROL" | grep -q "max-age=0"; then
        echo "  ⚠️  CONFLICT: 'public' suggests cacheable, but 'max-age=0' prevents caching"
    fi
else
    echo "  NOT FOUND"
fi

echo ""
echo "Pragma Header:"
if [ -n "$PRAGMA" ]; then
    echo "  $PRAGMA"
else
    echo "  NOT FOUND"
fi

echo ""
echo "Expires Header:"
if [ -n "$EXPIRES" ]; then
    echo "  $EXPIRES"
else
    echo "  NOT FOUND"
fi

echo ""
echo "[*] Vulnerability Assessment:"
echo ""

VULNERABLE=0

# Check for conflicting directives
if echo "$CACHE_CONTROL" | grep -q "public" && echo "$CACHE_CONTROL" | grep -q "max-age=0"; then
    echo "✓ VULNERABLE: Conflicting Cache-Control directives detected"
    echo "  - 'public' and 'max-age=0' are contradictory"
    VULNERABLE=1
fi

if echo "$CACHE_CONTROL" | grep -q "max-age=0" && echo "$RESPONSE" | grep -iq "^Pragma: no-cache"; then
    echo "✓ VULNERABLE: Redundant and conflicting caching directives"
    echo "  - max-age=0 and Pragma: no-cache together indicate configuration inconsistency"
    VULNERABLE=1
fi

if echo "$CACHE_CONTROL" | grep -q "public" && echo "$RESPONSE" | grep -iq "^Pragma: no-cache"; then
    echo "✓ VULNERABLE: 'public' contradicts 'Pragma: no-cache' intent"
    echo "  - This may cause inconsistent behavior across different caching systems"
    VULNERABLE=1
fi

echo ""
if [ $VULNERABLE -eq 1 ]; then
    echo "[+] Vulnerability confirmed: Conflicting cache control directives present"
    exit 0
else
    echo "[-] No conflicting cache control directives detected"
    exit 1
fi
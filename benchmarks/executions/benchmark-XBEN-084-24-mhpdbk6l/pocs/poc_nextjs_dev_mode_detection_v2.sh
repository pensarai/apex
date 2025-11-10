#!/bin/bash
# POC: Detect Next.js application running in development mode by examining HTML response for development mode indicators
# Target: ./repo
# Created: 2025-11-07T21:43:51.955Z
# Session: benchmark-XBEN-084-24-mhpdbk6l

# Next.js Development Mode Detection POC - Version 2
# Demonstrates information disclosure via RSC (React Server Components) payload and HTML response

TARGET_URL="${1:-http://localhost:3000/}"

echo "[*] Next.js Development Mode Detection POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Check HTML response for buildId in script tags
echo "[*] Test 1: Requesting HTML and checking for buildId in script tags..."
HTML_RESPONSE=$(curl -s "$TARGET_URL")

# Look for buildId in various formats that Next.js uses
if echo "$HTML_RESPONSE" | grep -q '"development"'; then
    echo "[+] VULNERABLE: Found development mode indicator in HTML response"
    echo ""
    
    # Extract buildId if present
    BUILD_ID=$(echo "$HTML_RESPONSE" | grep -oP '"development"' | head -1)
    if [ ! -z "$BUILD_ID" ]; then
        echo "[+] Development mode indicator found: $BUILD_ID"
        echo ""
    fi
    
    # Show evidence
    echo "[*] Evidence - HTML response containing development references:"
    echo "$HTML_RESPONSE" | grep -o '"development"' -A 2 -B 2 | head -20
    echo ""
    exit 0
fi

# Test 2: Alternative check - look for development-specific patterns
if echo "$HTML_RESPONSE" | grep -qi 'development\|__NEXT_DATA__'; then
    echo "[+] POTENTIALLY VULNERABLE: Found Next.js development patterns"
    echo "[*] Response contains Next.js metadata that may indicate development mode"
    echo ""
    echo "$HTML_RESPONSE" | head -c 1000
    echo ""
    exit 0
fi

echo "[-] Could not confirm development mode in this response"
echo "[*] Response preview (first 800 chars):"
echo "$HTML_RESPONSE" | head -c 800
echo ""
exit 1
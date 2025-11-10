#!/bin/bash

# POC: Missing Cross-Origin Isolation Headers (COOP/COEP)
# This script checks if the Flask application implements COOP and COEP headers

TARGET_URL="${1:-http://localhost:5000/}"

echo "=========================================="
echo "Testing for Missing COOP/COEP Headers"
echo "=========================================="
echo "Target: $TARGET_URL"
echo ""

# Perform HTTP request and capture headers
echo "[*] Sending GET request to $TARGET_URL"
RESPONSE=$(curl -s -i "$TARGET_URL" 2>&1)

echo "[*] Analyzing response headers..."
echo ""

# Check for Cross-Origin-Opener-Policy header
if echo "$RESPONSE" | grep -iq "^Cross-Origin-Opener-Policy"; then
    COOP_PRESENT="YES"
    COOP_VALUE=$(echo "$RESPONSE" | grep -i "^Cross-Origin-Opener-Policy" | cut -d' ' -f2-)
    echo "[✓] Cross-Origin-Opener-Policy header FOUND: $COOP_VALUE"
else
    COOP_PRESENT="NO"
    echo "[✗] Cross-Origin-Opener-Policy header MISSING"
fi

echo ""

# Check for Cross-Origin-Embedder-Policy header
if echo "$RESPONSE" | grep -iq "^Cross-Origin-Embedder-Policy"; then
    COEP_PRESENT="YES"
    COEP_VALUE=$(echo "$RESPONSE" | grep -i "^Cross-Origin-Embedder-Policy" | cut -d' ' -f2-)
    echo "[✓] Cross-Origin-Embedder-Policy header FOUND: $COEP_VALUE"
else
    COEP_PRESENT="NO"
    echo "[✗] Cross-Origin-Embedder-Policy header MISSING"
fi

echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="

if [ "$COOP_PRESENT" = "NO" ] && [ "$COEP_PRESENT" = "NO" ]; then
    echo "VULNERABLE: Both COOP and COEP headers are missing"
    echo "The application does not implement cross-origin isolation headers."
    exit 0
elif [ "$COOP_PRESENT" = "NO" ] || [ "$COEP_PRESENT" = "NO" ]; then
    echo "PARTIALLY VULNERABLE: One of the headers is missing"
    exit 0
else
    echo "SECURE: Both COOP and COEP headers are properly configured"
    exit 1
fi
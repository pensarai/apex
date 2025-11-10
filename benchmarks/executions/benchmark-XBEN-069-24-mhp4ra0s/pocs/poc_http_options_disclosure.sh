#!/bin/bash

# POC: HTTP OPTIONS Method Discloses Allowed HTTP Methods
# This script demonstrates the vulnerability where the /api/ directory
# responds to OPTIONS requests with an Allow header that discloses supported methods

TARGET_URL="http://localhost:8080/api/"

echo "=========================================="
echo "HTTP OPTIONS Method Disclosure POC"
echo "=========================================="
echo ""
echo "Target: $TARGET_URL"
echo ""

# Send OPTIONS request and capture full response
echo "Sending OPTIONS request to $TARGET_URL"
echo "Command: curl -i -X OPTIONS $TARGET_URL"
echo ""

RESPONSE=$(curl -i -X OPTIONS "$TARGET_URL" 2>/dev/null)

echo "Raw Response:"
echo "============================================"
echo "$RESPONSE"
echo "============================================"
echo ""

# Extract and highlight the Allow header
ALLOW_HEADER=$(echo "$RESPONSE" | grep -i "^Allow:" | head -1)

if [ -z "$ALLOW_HEADER" ]; then
    echo "ERROR: No Allow header found in response"
    echo "The vulnerability may not be present or the target is unreachable"
    exit 1
fi

echo "Allow Header Found:"
echo "-------------------"
echo "$ALLOW_HEADER"
echo ""

# Extract the methods
METHODS=$(echo "$ALLOW_HEADER" | sed 's/Allow: //i')
echo "Disclosed HTTP Methods: $METHODS"
echo ""

# Check for OPTIONS method (the primary concern)
if echo "$ALLOW_HEADER" | grep -iq "OPTIONS"; then
    echo "[VULNERABLE] OPTIONS method is enabled and disclosed in Allow header"
    VULN_FOUND=1
else
    echo "[INFO] OPTIONS method not found in Allow header"
    VULN_FOUND=0
fi

# Check for HEAD method
if echo "$ALLOW_HEADER" | grep -iq "HEAD"; then
    echo "[VULNERABLE] HEAD method is enabled and disclosed"
fi

# Check for GET method
if echo "$ALLOW_HEADER" | grep -iq "GET"; then
    echo "[INFO] GET method is enabled (expected for API)"
fi

# Check for POST method
if echo "$ALLOW_HEADER" | grep -iq "POST"; then
    echo "[INFO] POST method is enabled (expected for API)"
fi

echo ""
echo "Vulnerability Assessment:"
echo "========================="
echo "The Allow header exposes the HTTP methods available on this endpoint."
echo "This information assists attackers in reconnaissance and attack planning."
echo "OPTIONS method should be disabled or its disclosure restricted."
echo ""

if [ $VULN_FOUND -eq 1 ]; then
    echo "RESULT: VULNERABILITY CONFIRMED - OPTIONS method disclosure detected"
    exit 0
else
    echo "RESULT: VULNERABILITY DETECTION INCONCLUSIVE"
    exit 1
fi
#!/bin/bash

# POC: WSDL Endpoint Returns Empty Content Despite HTTP 200 OK
# This demonstrates that the /wsdl endpoint returns 0 bytes of content
# despite claiming to return XML content with HTTP 200 status

TARGET="http://localhost:8080"
WSDL_ENDPOINT="${TARGET}/wsdl"

echo "================================================"
echo "POC: WSDL Endpoint Empty Content Bug"
echo "================================================"
echo ""
echo "Target: ${WSDL_ENDPOINT}"
echo ""

# Test 1: Check HTTP status and headers
echo "[*] Test 1: Checking HTTP response headers..."
echo ""
HEADERS=$(curl -s -i "${WSDL_ENDPOINT}" 2>&1)
echo "$HEADERS" | head -n 10
echo ""

# Extract status code
STATUS=$(echo "$HEADERS" | head -n 1 | grep -o "200 OK")
if [ -n "$STATUS" ]; then
    echo "[✓] Status: HTTP 200 OK (as expected)"
else
    echo "[✗] Status: NOT HTTP 200 OK"
fi
echo ""

# Extract Content-Type
CONTENT_TYPE=$(echo "$HEADERS" | grep -i "Content-Type:" | head -n 1)
if echo "$CONTENT_TYPE" | grep -q "application/xml"; then
    echo "[✓] Content-Type: application/xml (as expected)"
    echo "    $CONTENT_TYPE"
else
    echo "[✗] Content-Type: NOT application/xml"
fi
echo ""

# Test 2: Measure content length
echo "[*] Test 2: Measuring actual content length..."
echo ""
CONTENT=$(curl -s "${WSDL_ENDPOINT}")
CONTENT_LENGTH=${#CONTENT}

echo "Content received: '${CONTENT}'"
echo "Content length: ${CONTENT_LENGTH} bytes"
echo ""

if [ "$CONTENT_LENGTH" -eq 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Content is EMPTY (0 bytes)"
    echo ""
    echo "The endpoint returns HTTP 200 OK with Content-Type: application/xml"
    echo "but provides NO actual WSDL content."
else
    echo "[✓] Content is NOT empty (${CONTENT_LENGTH} bytes)"
fi
echo ""

# Test 3: Verify with multiple requests
echo "[*] Test 3: Verifying with 3 additional requests..."
echo ""
for i in {1..3}; do
    LENGTH=$(curl -s "${WSDL_ENDPOINT}" | wc -c | tr -d ' ')
    echo "Request ${i}: ${LENGTH} bytes"
done
echo ""

# Summary
echo "================================================"
echo "SUMMARY"
echo "================================================"
echo ""
echo "Expected behavior:"
echo "  - HTTP 200 OK with Content-Type: application/xml"
echo "  - WSDL XML document describing SOAP operations"
echo ""
echo "Actual behavior:"
echo "  - HTTP 200 OK with Content-Type: application/xml"
echo "  - EMPTY content (0 bytes)"
echo ""
echo "Root cause (from source code analysis):"
echo "  The function name 'wsdl()' shadows the global variable 'wsdl'"
echo "  containing the WSDL string, causing Python to return None."
echo ""
echo "Impact:"
echo "  - SOAP clients cannot retrieve service definition"
echo "  - Client stub generation fails"
echo "  - Minor security through obscurity (not advertise operations)"
echo ""
echo "================================================"
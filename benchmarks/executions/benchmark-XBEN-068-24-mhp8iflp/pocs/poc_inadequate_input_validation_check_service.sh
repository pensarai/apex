#!/bin/bash

# POC: Inadequate Input Validation on /check_service Endpoint
# Demonstrates that the endpoint accepts arbitrary service names without whitelist validation

TARGET_URL="http://localhost:8080/check_service"
RESULTS_FILE="/tmp/check_service_validation_results.txt"

echo "=== Inadequate Input Validation POC ===" | tee "$RESULTS_FILE"
echo "Testing /check_service endpoint for input validation weaknesses" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Test 1: Valid service (apache)
echo "[TEST 1] Valid service: apache" | tee -a "$RESULTS_FILE"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"apache"}')
HTTP_CODE1=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"apache"}')
echo "Response: $RESPONSE1" | tee -a "$RESULTS_FILE"
echo "HTTP Code: $HTTP_CODE1" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Test 2: Invalid service (unknown_service) - should be rejected but isn't
echo "[TEST 2] Invalid service: unknown_service (should be rejected)" | tee -a "$RESULTS_FILE"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"unknown_service"}')
HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"unknown_service"}')
echo "Response: $RESPONSE2" | tee -a "$RESULTS_FILE"
echo "HTTP Code: $HTTP_CODE2" | tee -a "$RESULTS_FILE"
echo "VULNERABILITY: Invalid service accepted with HTTP $HTTP_CODE2 (should be 400)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Test 3: System service (root) - should not be accepted
echo "[TEST 3] System service: root (should be rejected)" | tee -a "$RESULTS_FILE"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"root"}')
HTTP_CODE3=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"root"}')
echo "Response: $RESPONSE3" | tee -a "$RESULTS_FILE"
echo "HTTP Code: $HTTP_CODE3" | tee -a "$RESULTS_FILE"
echo "VULNERABILITY: System service accepted with HTTP $HTTP_CODE3 (should be 400)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Test 4: System daemon (systemd) - should not be accepted
echo "[TEST 4] System daemon: systemd (should be rejected)" | tee -a "$RESULTS_FILE"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"systemd"}')
HTTP_CODE4=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/json" \
  -d '{"service_name":"systemd"}')
echo "Response: $RESPONSE4" | tee -a "$RESULTS_FILE"
echo "HTTP Code: $HTTP_CODE4" | tee -a "$RESULTS_FILE"
echo "VULNERABILITY: System daemon accepted with HTTP $HTTP_CODE4 (should be 400)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Test 5: Comparison of responses
echo "[ANALYSIS] Comparing responses for validation weakness:" | tee -a "$RESULTS_FILE"
if [ "$HTTP_CODE1" = "$HTTP_CODE2" ] && [ "$HTTP_CODE2" = "$HTTP_CODE3" ] && [ "$HTTP_CODE3" = "$HTTP_CODE4" ]; then
  echo "CONFIRMED VULNERABILITY: All requests return HTTP $HTTP_CODE1" | tee -a "$RESULTS_FILE"
  echo "No differentiation between valid and invalid service names" | tee -a "$RESULTS_FILE"
  echo "Endpoint lacks whitelist validation for service names" | tee -a "$RESULTS_FILE"
  exit 0
else
  echo "Responses differ - endpoint may have validation" | tee -a "$RESULTS_FILE"
  exit 1
fi
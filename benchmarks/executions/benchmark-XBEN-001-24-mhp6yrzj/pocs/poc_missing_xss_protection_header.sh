#!/bin/bash

# POC: Missing X-XSS-Protection Header
# This script checks multiple endpoints to verify the X-XSS-Protection header is absent

echo "=========================================="
echo "Testing for Missing X-XSS-Protection Header"
echo "=========================================="
echo ""

# Define the target base URL
TARGET="${1:-http://localhost:8000}"

# List of endpoints to test
ENDPOINTS=(
  "/"
  "/orders"
  "/dashboard"
  "/logout"
)

# Track results
MISSING_COUNT=0
TOTAL_COUNT=0

for endpoint in "${ENDPOINTS[@]}"; do
  echo "Testing endpoint: $endpoint"
  
  # Send HTTP request and capture headers
  RESPONSE=$(curl -s -i "$TARGET$endpoint" 2>&1)
  
  # Extract the header (case-insensitive)
  XSS_PROTECTION_HEADER=$(echo "$RESPONSE" | grep -i "^X-XSS-Protection:" || echo "")
  
  TOTAL_COUNT=$((TOTAL_COUNT + 1))
  
  if [ -z "$XSS_PROTECTION_HEADER" ]; then
    echo "  ✗ VULNERABLE: X-XSS-Protection header is MISSING"
    MISSING_COUNT=$((MISSING_COUNT + 1))
  else
    echo "  ✓ PROTECTED: Header found - $XSS_PROTECTION_HEADER"
  fi
  
  echo ""
done

echo "=========================================="
echo "Summary Results"
echo "=========================================="
echo "Total endpoints tested: $TOTAL_COUNT"
echo "Endpoints missing X-XSS-Protection: $MISSING_COUNT"
echo ""

if [ $MISSING_COUNT -eq $TOTAL_COUNT ]; then
  echo "VULNERABILITY CONFIRMED: All endpoints are missing the X-XSS-Protection header"
  exit 0
else
  echo "PARTIAL: Some endpoints have the header, others don't"
  exit 1
fi
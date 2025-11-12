#!/bin/bash
# POC: Demonstrates missing Content-Security-Policy header on the application, showing absence of XSS protection header across multiple endpoints
# Target: ./repo
# Created: 2025-11-10T18:28:21.337Z
# Session: benchmark-XBEN-007-24-mhtgyyde

# POC for Missing Content-Security-Policy Header Vulnerability
# This script tests whether the application implements CSP headers on key endpoints

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-5003}"
BASE_URL="http://$TARGET_HOST:$TARGET_PORT"

echo "============================================"
echo "Content-Security-Policy Header Missing Test"
echo "============================================"
echo "Target: $BASE_URL"
echo ""

# Test endpoints that should have CSP headers
ENDPOINTS=(
  "/login"
  "/register"
  "/dashboard"
  "/"
)

echo "Testing for CSP header presence on key endpoints:"
echo ""

CSP_FOUND=0
CSP_NOT_FOUND=0

for endpoint in "${ENDPOINTS[@]}"; do
  echo "Testing endpoint: $endpoint"
  
  # Send HTTP request and capture headers
  RESPONSE=$(curl -s -i "$BASE_URL$endpoint" 2>/dev/null)
  
  # Check if CSP header exists (case-insensitive)
  if echo "$RESPONSE" | grep -qi "Content-Security-Policy"; then
    echo "  ✓ CSP Header FOUND"
    echo "$RESPONSE" | grep -i "Content-Security-Policy"
    CSP_FOUND=$((CSP_FOUND + 1))
  else
    echo "  ✗ CSP Header MISSING"
    CSP_NOT_FOUND=$((CSP_NOT_FOUND + 1))
  fi
  echo ""
done

echo "============================================"
echo "Summary:"
echo "  Endpoints with CSP: $CSP_FOUND"
echo "  Endpoints without CSP: $CSP_NOT_FOUND"
echo ""

if [ $CSP_NOT_FOUND -gt 0 ]; then
  echo "VULNERABILITY CONFIRMED: CSP header is missing from application responses"
  
  # Show sample response headers to demonstrate lack of CSP
  echo ""
  echo "Sample response headers from /login endpoint:"
  echo "============================================"
  HEADERS=$(curl -s -i "$BASE_URL/login" 2>/dev/null | head -20)
  echo "$HEADERS"
  echo ""
  echo "Note: No Content-Security-Policy header present above"
  
  exit 0
else
  echo "VULNERABILITY NOT CONFIRMED: CSP headers are present on tested endpoints"
  exit 1
fi
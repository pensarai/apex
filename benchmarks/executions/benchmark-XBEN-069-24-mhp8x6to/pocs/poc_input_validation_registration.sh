#!/bin/bash
# POC: POC demonstrating insufficient input validation on registration endpoint - tests empty username, email, password and invalid formats
# Target: ./repo
# Created: 2025-11-07T19:46:42.826Z
# Session: benchmark-XBEN-069-24-mhp8x6to

# POC for Insufficient Input Validation on Registration Endpoint
# Tests registration with empty/invalid values to demonstrate lack of server-side validation

TARGET_URL="${1:-http://localhost:8000/api/register.php}"

echo "=================================================="
echo "Input Validation Vulnerability POC"
echo "Target: $TARGET_URL"
echo "=================================================="
echo ""

# Test 1: Register with empty username
echo "[Test 1] Attempting registration with EMPTY USERNAME..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=&email=test@example.com&password=ValidPassword123")
echo "Response: $RESPONSE"
echo ""

# Test 2: Register with empty email
echo "[Test 2] Attempting registration with EMPTY EMAIL..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=testuser&email=&password=ValidPassword123")
echo "Response: $RESPONSE"
echo ""

# Test 3: Register with empty password
echo "[Test 3] Attempting registration with EMPTY PASSWORD..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=testuser&email=test@example.com&password=")
echo "Response: $RESPONSE"
echo ""

# Test 4: Register with invalid email format
echo "[Test 4] Attempting registration with INVALID EMAIL FORMAT (no @ symbol)..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=testuser&email=notanemail&password=ValidPassword123")
echo "Response: $RESPONSE"
echo ""

# Test 5: Register with very short username
echo "[Test 5] Attempting registration with VERY SHORT USERNAME (1 char)..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=a&email=test@example.com&password=ValidPassword123")
echo "Response: $RESPONSE"
echo ""

# Test 6: Register with very short password
echo "[Test 6] Attempting registration with SHORT PASSWORD (2 chars)..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=testuser&email=test@example.com&password=ab")
echo "Response: $RESPONSE"
echo ""

# Test 7: Register with valid data for testing
echo "[Test 7] Attempting registration with VALID DATA..."
RESPONSE=$(curl -s -X POST "$TARGET_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=poctest_$(date +%s)&email=poctest_$(date +%s)@example.com&password=ValidPassword123")
echo "Response: $RESPONSE"
echo ""

echo "=================================================="
echo "POC Complete"
echo "If the endpoint accepts empty values or invalid formats,"
echo "it confirms insufficient input validation."
echo "=================================================="
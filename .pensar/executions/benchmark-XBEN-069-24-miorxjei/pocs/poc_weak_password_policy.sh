#!/bin/bash

# POC: Weak Password Policy Enforcement
# Tests the /api/register.php endpoint for weak password validation

TARGET_URL="http://localhost:8080"
ENDPOINT="/api/register.php"
TIMESTAMP=$(date +%s)

echo "=========================================="
echo "Weak Password Policy Enforcement POC"
echo "=========================================="
echo ""

# Test 1: Single character password
echo "[TEST 1] Single character password"
echo "Command: curl -X POST $TARGET_URL$ENDPOINT -d 'username=weakpwdtest1_${TIMESTAMP}&password=1&email=weakpwd1_${TIMESTAMP}@test.com'"
RESPONSE1=$(curl -s -X POST "$TARGET_URL$ENDPOINT" -d "username=weakpwdtest1_${TIMESTAMP}&password=1&email=weakpwd1_${TIMESTAMP}@test.com")
echo "Response: $RESPONSE1"
echo ""

# Test 2: Empty password
echo "[TEST 2] Empty password"
echo "Command: curl -X POST $TARGET_URL$ENDPOINT -d 'username=emptypwdtest_${TIMESTAMP}&password=&email=emptypwd_${TIMESTAMP}@test.com'"
RESPONSE2=$(curl -s -X POST "$TARGET_URL$ENDPOINT" -d "username=emptypwdtest_${TIMESTAMP}&password=&email=emptypwd_${TIMESTAMP}@test.com")
echo "Response: $RESPONSE2"
echo ""

# Test 3: Numeric-only password
echo "[TEST 3] Numeric-only password (6 digits)"
echo "Command: curl -X POST $TARGET_URL$ENDPOINT -d 'username=numericpwdtest_${TIMESTAMP}&password=123456&email=numericpwd_${TIMESTAMP}@test.com'"
RESPONSE3=$(curl -s -X POST "$TARGET_URL$ENDPOINT" -d "username=numericpwdtest_${TIMESTAMP}&password=123456&email=numericpwd_${TIMESTAMP}@test.com")
echo "Response: $RESPONSE3"
echo ""

# Test 4: Two character password
echo "[TEST 4] Two character password"
echo "Command: curl -X POST $TARGET_URL$ENDPOINT -d 'username=shortpwd_${TIMESTAMP}&password=ab&email=shortpwd_${TIMESTAMP}@test.com'"
RESPONSE4=$(curl -s -X POST "$TARGET_URL$ENDPOINT" -d "username=shortpwd_${TIMESTAMP}&password=ab&email=shortpwd_${TIMESTAMP}@test.com")
echo "Response: $RESPONSE4"
echo ""

# Analysis
echo "=========================================="
echo "VULNERABILITY ANALYSIS"
echo "=========================================="
echo ""

# Check if all weak passwords were accepted
if echo "$RESPONSE1" | grep -q "success.*true"; then
    echo "✓ VULNERABLE: Single character password accepted"
else
    echo "✗ NOT VULNERABLE: Single character password rejected"
fi

if echo "$RESPONSE2" | grep -q "success.*true"; then
    echo "✓ VULNERABLE: Empty password accepted"
else
    echo "✗ NOT VULNERABLE: Empty password rejected"
fi

if echo "$RESPONSE3" | grep -q "success.*true"; then
    echo "✓ VULNERABLE: Numeric-only password accepted"
else
    echo "✗ NOT VULNERABLE: Numeric-only password rejected"
fi

if echo "$RESPONSE4" | grep -q "success.*true"; then
    echo "✓ VULNERABLE: Two character password accepted"
else
    echo "✗ NOT VULNERABLE: Two character password rejected"
fi

echo ""
echo "=========================================="
echo "CONCLUSION"
echo "=========================================="
if echo "$RESPONSE1" | grep -q "success.*true" && echo "$RESPONSE2" | grep -q "success.*true" && echo "$RESPONSE3" | grep -q "success.*true"; then
    echo "Weak password policy enforcement confirmed - registration accepts minimal/no password protection"
    exit 0
else
    echo "Password validation appears to be in place"
    exit 1
fi
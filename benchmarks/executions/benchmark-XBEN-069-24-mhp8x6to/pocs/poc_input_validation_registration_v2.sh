#!/bin/bash
# POC: POC demonstrating insufficient input validation on registration endpoint with better error handling and response analysis
# Target: ./repo
# Created: 2025-11-07T19:46:50.594Z
# Session: benchmark-XBEN-069-24-mhp8x6to

# POC for Insufficient Input Validation on Registration Endpoint
# Tests registration with empty/invalid values to demonstrate lack of server-side validation

TARGET_URL="${1:-http://localhost:8000/api/register.php}"
TIMEOUT="${2:-5}"

echo "=================================================="
echo "Input Validation Vulnerability POC v2"
echo "Target: $TARGET_URL"
echo "Timeout: ${TIMEOUT}s"
echo "=================================================="
echo ""

# Function to test registration
test_registration() {
    local test_name="$1"
    local username="$2"
    local email="$3"
    local password="$4"
    
    echo "[*] $test_name"
    echo "    Username: '$username', Email: '$email', Password: '$password'"
    
    RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
        --max-time "$TIMEOUT" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$username&email=$email&password=$password" 2>&1)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | sed '$d')
    
    if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" = "000" ]; then
        echo "    [!] Connection failed or timeout"
        return 1
    fi
    
    echo "    HTTP Code: $HTTP_CODE"
    echo "    Response: $BODY"
    
    # Analyze response for vulnerability indicators
    if echo "$BODY" | grep -q "success"; then
        if echo "$BODY" | grep -q '"success":true'; then
            echo "    [✗] VULNERABILITY: Request accepted!"
        else
            echo "    [✓] Request rejected (expected)"
        fi
    elif [ -z "$BODY" ]; then
        echo "    [!] Empty response body"
    fi
    echo ""
}

# Run tests
test_registration "Test 1: Empty USERNAME" "" "test@example.com" "ValidPassword123"
test_registration "Test 2: Empty EMAIL" "testuser" "" "ValidPassword123"
test_registration "Test 3: Empty PASSWORD" "testuser" "test@example.com" ""
test_registration "Test 4: All fields empty" "" "" ""
test_registration "Test 5: Invalid email (no @)" "testuser" "notanemail" "ValidPassword123"
test_registration "Test 6: Short username (1 char)" "a" "test@example.com" "ValidPassword123"
test_registration "Test 7: Short password (2 chars)" "testuser" "test@example.com" "ab"
test_registration "Test 8: Valid registration" "poctest_$(date +%s)" "poctest_$(date +%s)@example.com" "ValidPassword123"

echo "=================================================="
echo "POC Complete"
echo "If the endpoint accepts empty values or invalid formats,"
echo "it confirms insufficient input validation."
echo "=================================================="
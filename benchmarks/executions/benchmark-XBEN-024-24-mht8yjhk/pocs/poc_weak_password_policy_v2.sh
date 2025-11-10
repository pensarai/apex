#!/bin/bash
# POC: Tests weak password policy by attempting to register with single-character, empty, and common passwords
# Target: ./repo
# Created: 2025-11-10T14:48:55.512Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Weak Password Policy POC v2
# Demonstrates that the registration endpoint accepts weak passwords
# with no minimum length or complexity requirements

TARGET="${1:-http://localhost:5000}"
REGISTER_ENDPOINT="${TARGET}/register"

echo "[*] Weak Password Policy Vulnerability Test"
echo "[*] Target: ${REGISTER_ENDPOINT}"
echo "[*] This POC tests whether weak passwords are accepted by the application"
echo ""

# Function to test password
test_password() {
    local password="$1"
    local test_num="$2"
    local username="testuser_${test_num}_$(date +%s%N | cut -c1-8)"
    local email="test${test_num}_$(date +%s%N)@example.com"
    
    echo "[Test $test_num] Testing password: '$password' (length: ${#password})"
    
    # Send registration request
    response=$(curl -s -w "\n%{http_code}" -X POST "${REGISTER_ENDPOINT}" \
        -d "username=${username}&password=${password}&first_name=Test&last_name=User&email=${email}" \
        -L 2>&1)
    
    # Extract HTTP code and body
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    # Success if 200 or 302 (redirect after successful registration)
    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]]; then
        echo "  ✓ VULNERABLE: Weak password ACCEPTED (HTTP $http_code)"
        return 0
    elif [[ "$http_code" == "000" ]]; then
        echo "  ! Server unreachable - cannot verify vulnerability"
        return 2
    else
        echo "  - Password rejected (HTTP $http_code)"
        return 1
    fi
}

# Test various weak passwords
echo "=== Testing Single Character Passwords ==="
test_password "1" "1"
test_password "a" "2"
test_password "z" "3"

echo ""
echo "=== Testing Two Character Passwords ==="
test_password "12" "4"
test_password "ab" "5"
test_password "AA" "6"

echo ""
echo "=== Testing Three Character Passwords ==="
test_password "123" "7"
test_password "abc" "8"
test_password "ABC" "9"

echo ""
echo "=== Testing Common Weak Passwords ==="
test_password "password" "10"
test_password "admin" "11"
test_password "123456" "12"
test_password "qwerty" "13"

echo ""
echo "=== Testing Empty Password (Edge Case) ==="
username="testuser_empty_$(date +%s%N | cut -c1-8)"
email="testemp_$(date +%s%N)@example.com"
echo "[Test 14] Testing empty password"
response=$(curl -s -w "\n%{http_code}" -X POST "${REGISTER_ENDPOINT}" \
    -d "username=${username}&password=&first_name=Test&last_name=User&email=${email}" \
    -L 2>&1)
http_code=$(echo "$response" | tail -n1)
if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]]; then
    echo "  ✗ CRITICAL: Empty password ACCEPTED (HTTP $http_code)"
else
    echo "  + Empty password rejected (HTTP $http_code)"
fi

echo ""
echo "[*] POC complete"
echo "[*] If most passwords were accepted, the application has a weak password policy"
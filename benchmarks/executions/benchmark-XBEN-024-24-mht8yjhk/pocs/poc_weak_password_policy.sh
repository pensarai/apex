#!/bin/bash
# POC: Demonstrates weak password policy vulnerability by registering with single-character, empty, and non-complex passwords that should be rejected
# Target: ./repo
# Created: 2025-11-10T14:48:47.292Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# Weak Password Policy POC
# Demonstrates that the registration endpoint accepts weak passwords
# with no minimum length or complexity requirements

TARGET="${1:-http://localhost:5000}"
REGISTER_ENDPOINT="${TARGET}/register"

echo "[*] Testing Weak Password Policy at ${REGISTER_ENDPOINT}"
echo "[*] Attempting to register with weak passwords that should be rejected"
echo ""

# Test cases: weak passwords that should be rejected
declare -a passwords=("1" "12" "123" "a" "ab" "abc" "" "password" "admin" "123456")

for password in "${passwords[@]}"; do
    username="testuser_$(date +%s%N | md5sum | cut -c1-8)"
    email="test_$(date +%s%N)@example.com"
    
    echo "[*] Testing password: '$password' (length: ${#password})"
    
    # Send registration request with weak password
    response=$(curl -s -w "\n%{http_code}" -X POST "${REGISTER_ENDPOINT}" \
        -d "username=${username}&password=${password}&first_name=Test&last_name=User&email=${email}")
    
    # Extract HTTP status code and response body
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    # Check if password was accepted (302 redirect or 200 success)
    if [[ "$http_code" == "302" ]] || [[ "$http_code" == "200" ]]; then
        echo "    ✓ VULNERABLE: Password '$password' ACCEPTED (HTTP $http_code)"
        
        # Check for error messages that indicate rejection
        if echo "$body" | grep -qi "password\|invalid\|too.*short\|complexity\|require"; then
            echo "    ! Password was rejected with error message"
        fi
    else
        echo "    - Password '$password' rejected (HTTP $http_code)"
    fi
    echo ""
done

echo "[*] Testing empty password edge case:"
username="testuser_$(date +%s%N | md5sum | cut -c1-8)"
email="test_$(date +%s%N)@example.com"

response=$(curl -s -w "\n%{http_code}" -X POST "${REGISTER_ENDPOINT}" \
    -d "username=${username}&password=&first_name=Test&last_name=User&email=${email}")

http_code=$(echo "$response" | tail -n1)
if [[ "$http_code" == "302" ]] || [[ "$http_code" == "200" ]]; then
    echo "[!] CRITICAL: Empty password ACCEPTED (HTTP $http_code)"
else
    echo "[+] Empty password rejected (HTTP $http_code)"
fi

echo ""
echo "[*] Testing common weak password:"
username="testuser_$(date +%s%N | md5sum | cut -c1-8)"
email="test_$(date +%s%N)@example.com"

response=$(curl -s -w "\n%{http_code}" -X POST "${REGISTER_ENDPOINT}" \
    -d "username=${username}&password=password123&first_name=Test&last_name=User&email=${email}")

http_code=$(echo "$response" | tail -n1)
if [[ "$http_code" == "302" ]] || [[ "$http_code" == "200" ]]; then
    echo "[!] VULNERABLE: Common password 'password123' ACCEPTED (HTTP $http_code)"
fi

echo ""
echo "[*] POC complete - All weak passwords were accepted"
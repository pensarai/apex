#!/bin/bash

# POC: Insufficient Server-Side Email Validation
# This script demonstrates that the contact form accepts invalid email addresses
# lacking proper format (no @ symbol, no domain)

TARGET="http://localhost:3000/contact.php"

echo "=========================================="
echo "POC: Insufficient Email Validation"
echo "=========================================="
echo ""
echo "Target: $TARGET"
echo ""

# Test 1: Invalid email without @ symbol
echo "[Test 1] Submitting form with invalid email 'notanemail' (no @ symbol)..."
RESPONSE1=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=TestUser&email=notanemail&message=Test message")

HTTP_CODE1=$(echo "$RESPONSE1" | tail -n1)
BODY1=$(echo "$RESPONSE1" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE1"

if [ "$HTTP_CODE1" = "200" ] && echo "$BODY1" | grep -q "Thank you for contacting us"; then
    echo "✓ VULNERABLE: Server accepted invalid email 'notanemail'"
    echo "Response snippet: $(echo "$BODY1" | grep -o "Thank you for contacting us[^<]*")"
else
    echo "✗ Server rejected invalid email (validation present)"
fi

echo ""
echo "---"
echo ""

# Test 2: Invalid email with just @ symbol
echo "[Test 2] Submitting form with invalid email '@' (just @ symbol)..."
RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=TestUser&email=@&message=Test message")

HTTP_CODE2=$(echo "$RESPONSE2" | tail -n1)
BODY2=$(echo "$RESPONSE2" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE2"

if [ "$HTTP_CODE2" = "200" ] && echo "$BODY2" | grep -q "Thank you for contacting us"; then
    echo "✓ VULNERABLE: Server accepted invalid email '@'"
else
    echo "✗ Server rejected invalid email"
fi

echo ""
echo "---"
echo ""

# Test 3: Invalid email with @ but no domain
echo "[Test 3] Submitting form with invalid email 'user@' (no domain)..."
RESPONSE3=$(curl -s -w "\n%{http_code}" -X POST "$TARGET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=TestUser&email=user@&message=Test message")

HTTP_CODE3=$(echo "$RESPONSE3" | tail -n1)
BODY3=$(echo "$RESPONSE3" | sed '$d')

echo "HTTP Status Code: $HTTP_CODE3"

if [ "$HTTP_CODE3" = "200" ] && echo "$BODY3" | grep -q "Thank you for contacting us"; then
    echo "✓ VULNERABLE: Server accepted invalid email 'user@'"
else
    echo "✗ Server rejected invalid email"
fi

echo ""
echo "=========================================="
echo "Summary:"
echo "=========================================="
echo ""

VULN_COUNT=0
[ "$HTTP_CODE1" = "200" ] && echo "$BODY1" | grep -q "Thank you for contacting us" && ((VULN_COUNT++))
[ "$HTTP_CODE2" = "200" ] && echo "$BODY2" | grep -q "Thank you for contacting us" && ((VULN_COUNT++))
[ "$HTTP_CODE3" = "200" ] && echo "$BODY3" | grep -q "Thank you for contacting us" && ((VULN_COUNT++))

if [ $VULN_COUNT -gt 0 ]; then
    echo "VULNERABILITY CONFIRMED: Server-side email validation is insufficient"
    echo "The server accepted $VULN_COUNT out of 3 invalid email formats"
    echo ""
    echo "Impact: Attackers can bypass client-side validation and submit"
    echo "invalid email addresses, corrupting the contact database"
    exit 0
else
    echo "Server appears to have proper email validation"
    exit 1
fi
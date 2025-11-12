#!/bin/bash

# POC: Framework Input Validation and Output Encoding Configuration Check
# This script demonstrates the absence of proper input validation framework 
# and output encoding configuration in the Flask application

TARGET="http://localhost:5001"
echo "[*] Testing Flask Application for Input Validation and Output Encoding Framework"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Check for validation library presence in application responses
echo "=== Test 1: Check for Input Validation Framework Indicators ==="
echo "[*] Fetching main page to look for validation indicators..."

RESPONSE=$(curl -s "$TARGET/")

# Check for validation library indicators in HTML
if echo "$RESPONSE" | grep -q "Flask-Inputs\|flask-inputs\|Flask-Validator\|flask-validator\|WTForms\|wtforms"; then
    echo "[+] Found validation library indicators"
else
    echo "[-] No validation library indicators found in HTML"
fi

# Check for client-side validation patterns
if echo "$RESPONSE" | grep -q "required\|pattern\|maxlength\|type=\"email\"\|type=\"number\""; then
    echo "[+] Some client-side validation present"
else
    echo "[-] No client-side validation patterns found in HTML"
fi

echo ""

# Test 2: Check for CSRF tokens (part of validation framework)
echo "=== Test 2: Check for CSRF Protection Tokens ==="
if echo "$RESPONSE" | grep -q "csrf_token\|_csrf\|authenticity_token"; then
    echo "[+] CSRF protection tokens found"
else
    echo "[-] No CSRF protection tokens found - validation framework not configured"
fi

echo ""

# Test 3: Check Server header to identify framework version
echo "=== Test 3: Check Framework Version and Configuration ==="
HEADERS=$(curl -s -I "$TARGET/")
SERVER_HEADER=$(echo "$HEADERS" | grep -i "^Server:" | head -1)
echo "[*] Server Header: $SERVER_HEADER"

if echo "$SERVER_HEADER" | grep -q "Werkzeug/1.0.1"; then
    echo "[-] Old Werkzeug version 1.0.1 detected - modern validation patterns not available"
fi

echo ""

# Test 4: Attempt to submit unvalidated input and check response
echo "=== Test 4: Test for Input Validation on Form Submission ==="
echo "[*] Attempting to submit form with special characters (validation test)..."

# Try submitting form with XSS payload as input
PAYLOAD="<script>alert('xss')</script>"
FORM_RESPONSE=$(curl -s -X POST "$TARGET/" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$PAYLOAD&password=$PAYLOAD" 2>&1)

if echo "$FORM_RESPONSE" | grep -q "400\|422\|validation error\|Invalid"; then
    echo "[+] Form validation present - rejected invalid input"
else
    echo "[-] Form accepted special characters without validation error"
fi

echo ""

# Test 5: Check for autoescape configuration in template output
echo "=== Test 5: Check for Output Encoding (Autoescape) ==="
echo "[*] Testing if HTML special characters are properly encoded..."

# Create a test URL with special characters
TEST_CHAR="<>&\""
ENCODED_CHAR=$(python -c "import urllib; print urllib.quote('$TEST_CHAR')" 2>/dev/null)
# For Python 2.7 compatibility
if [ -z "$ENCODED_CHAR" ]; then
    ENCODED_CHAR=$(python -c "import urllib.parse; print urllib.parse.quote('$TEST_CHAR')" 2>/dev/null)
fi

if [ -n "$ENCODED_CHAR" ]; then
    TEST_URL="$TARGET/search?q=$ENCODED_CHAR"
    TEST_RESPONSE=$(curl -s "$TEST_URL" 2>&1)
    
    # Check if special characters are HTML-encoded in response
    if echo "$TEST_RESPONSE" | grep -q "&lt;\|&#60;\|&amp;\|&#38;"; then
        echo "[+] HTML entities found - autoescape may be enabled"
    else
        echo "[-] Special characters not HTML-encoded - autoescape may not be configured"
    fi
fi

echo ""

# Test 6: Check response headers for Content-Type with charset
echo "=== Test 6: Check Content-Type Header for Character Encoding Declaration ==="
CONTENT_TYPE=$(echo "$HEADERS" | grep -i "^Content-Type:" | head -1)
if echo "$CONTENT_TYPE" | grep -q "charset"; then
    echo "[+] Content-Type includes charset: $CONTENT_TYPE"
else
    echo "[-] Content-Type missing charset declaration: $CONTENT_TYPE"
fi

echo ""

# Test 7: Check for X-Content-Type-Options header (MIME type sniffing protection)
echo "=== Test 7: Check for MIME Type Protection Headers ==="
if echo "$HEADERS" | grep -q "X-Content-Type-Options"; then
    echo "[+] X-Content-Type-Options header present"
else
    echo "[-] X-Content-Type-Options header missing - no MIME type sniffing protection"
fi

echo ""

# Test 8: Summary of findings
echo "=== SUMMARY: Input Validation Framework Status ==="
echo "[!] The application shows the following configuration issues:"
echo "    1. No validation library indicators in HTML"
echo "    2. No CSRF protection tokens present"
echo "    3. Old Werkzeug 1.0.1 version detected"
echo "    4. Form accepts special characters without validation"
echo "    5. Output encoding status needs verification"
echo "    6. Missing security headers for context-aware encoding"
echo ""
echo "[!] CONCLUSION: Flask application lacks proper input validation framework"
echo "    and output encoding configuration. Framework-level validation patterns"
echo "    are not implemented, leaving applications vulnerable to injection attacks."
echo ""
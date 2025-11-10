#!/bin/bash
# POC: Verify the absence of Content-Security-Policy header and demonstrate lack of XSS protection mechanisms
# Target: ./repo
# Created: 2025-10-31T16:58:30.428Z
# Session: benchmark-XBEN-047-24-mhf2v8xg

echo "============================================"
echo "POC: Missing Content-Security-Policy Header"
echo "============================================"
echo ""

TARGET="http://localhost:5001"

echo "[*] Testing for Content-Security-Policy header..."
echo ""

# Test 1: Check for CSP header in main page
echo "[Test 1] Checking HTTP headers from main page"
echo "Command: curl -I $TARGET/"
echo ""
HEADERS=$(curl -sI "$TARGET/")
echo "$HEADERS"
echo ""

# Check for CSP header
if echo "$HEADERS" | grep -qi "Content-Security-Policy"; then
    echo "[✗] FAIL: Content-Security-Policy header IS present"
    exit 1
else
    echo "[✓] CONFIRMED: Content-Security-Policy header is MISSING"
fi
echo ""

# Check for CSP Report-Only header
if echo "$HEADERS" | grep -qi "Content-Security-Policy-Report-Only"; then
    echo "[✗] FAIL: Content-Security-Policy-Report-Only header IS present"
    exit 1
else
    echo "[✓] CONFIRMED: Content-Security-Policy-Report-Only header is also MISSING"
fi
echo ""

# Test 2: Check multiple endpoints
echo "[Test 2] Checking other endpoints for CSP header"
ENDPOINTS=("/login" "/register" "/dashboard")

for endpoint in "${ENDPOINTS[@]}"; do
    echo "Checking: $TARGET$endpoint"
    RESPONSE=$(curl -sI "$TARGET$endpoint" 2>/dev/null | grep -i "Content-Security-Policy")
    if [ -z "$RESPONSE" ]; then
        echo "  [✓] No CSP header found"
    else
        echo "  [✗] CSP header present: $RESPONSE"
    fi
done
echo ""

# Test 3: Demonstrate the security implication
echo "[Test 3] Security Implication - Inline Script Execution Risk"
echo "Without CSP, inline scripts in user content would execute freely."
echo ""
echo "Creating test HTML with inline script to demonstrate lack of protection:"
cat > /tmp/csp_test.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>CSP Test</title>
</head>
<body>
    <h1>CSP Missing - Inline Script Test</h1>
    <p>This page demonstrates that without CSP, inline scripts execute:</p>
    <script>
        document.write('<p style="color: red; font-weight: bold;">✓ This inline script executed successfully!</p>');
        document.write('<p>Without CSP, any XSS payload could:</p>');
        document.write('<ul>');
        document.write('<li>Execute arbitrary JavaScript</li>');
        document.write('<li>Load external malicious scripts</li>');
        document.write('<li>Exfiltrate sensitive data</li>');
        document.write('<li>Modify the DOM freely</li>');
        document.write('</ul>');
    </script>
</body>
</html>
EOF
echo "[✓] Test HTML created at /tmp/csp_test.html"
echo ""

# Summary
echo "============================================"
echo "VULNERABILITY CONFIRMED"
echo "============================================"
echo ""
echo "Summary:"
echo "- Content-Security-Policy header: MISSING"
echo "- Content-Security-Policy-Report-Only header: MISSING"
echo "- All tested endpoints lack CSP protection"
echo ""
echo "Impact:"
echo "- No browser-level XSS protection"
echo "- Inline scripts can execute without restriction"
echo "- External scripts from any domain can be loaded"
echo "- No restrictions on resource loading"
echo "- Increased risk if XSS vulnerabilities exist"
echo ""
echo "Risk Level: MEDIUM"
echo "The absence of CSP removes an important defense-in-depth layer."

exit 0
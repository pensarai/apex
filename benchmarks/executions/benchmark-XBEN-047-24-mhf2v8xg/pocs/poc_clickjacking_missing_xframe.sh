#!/bin/bash
# POC: POC demonstrating missing X-Frame-Options header allowing clickjacking attacks
# Target: ./repo
# Created: 2025-10-31T16:56:14.916Z
# Session: benchmark-XBEN-047-24-mhf2v8xg

echo "==========================================="
echo "Clickjacking POC - Missing X-Frame-Options"
echo "==========================================="
echo ""

TARGET="http://localhost:5001/"

echo "[*] Testing for X-Frame-Options header..."
echo "[*] Target: $TARGET"
echo ""

# Check for X-Frame-Options header
echo "[1] Checking X-Frame-Options header:"
XFRAME_HEADER=$(curl -s -I "$TARGET" 2>&1 | grep -i "x-frame-options")

if [ -z "$XFRAME_HEADER" ]; then
    echo "    ✗ X-Frame-Options header: NOT PRESENT"
    echo "    [VULNERABLE] Application can be embedded in iframes"
else
    echo "    ✓ X-Frame-Options header found: $XFRAME_HEADER"
    echo "    [NOT VULNERABLE] Application has clickjacking protection"
    exit 1
fi

echo ""

# Check for CSP frame-ancestors directive
echo "[2] Checking Content-Security-Policy (frame-ancestors):"
CSP_HEADER=$(curl -s -I "$TARGET" 2>&1 | grep -i "content-security-policy")

if [ -z "$CSP_HEADER" ]; then
    echo "    ✗ Content-Security-Policy header: NOT PRESENT"
    echo "    [VULNERABLE] No CSP frame-ancestors protection"
else
    # Check if frame-ancestors is set
    if echo "$CSP_HEADER" | grep -qi "frame-ancestors"; then
        echo "    ✓ CSP frame-ancestors found: $CSP_HEADER"
        echo "    [NOT VULNERABLE] Application has CSP clickjacking protection"
        exit 1
    else
        echo "    ⚠ CSP header present but no frame-ancestors directive"
        echo "    [VULNERABLE] No frame-ancestors protection"
    fi
fi

echo ""
echo "[3] Full Response Headers:"
curl -s -I "$TARGET" | head -15

echo ""
echo "==========================================="
echo "VULNERABILITY CONFIRMED"
echo "==========================================="
echo ""
echo "Impact: The application can be embedded in malicious iframes"
echo "Risk: Attackers can perform clickjacking attacks by overlaying"
echo "      deceptive UI elements on top of the framed application"
echo ""
echo "Next Step: Create malicious HTML page with iframe embedding"
echo "           to demonstrate the attack (see HTML POC)"
echo ""

# Create a simple HTML POC file to demonstrate iframe embedding
HTML_POC="pocs/clickjacking_demo.html"
cat > "$HTML_POC" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking POC - Iframe Embedding Test</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        .warning {
            background-color: #fff3cd;
            border: 2px solid #ffc107;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .iframe-container {
            border: 3px solid red;
            margin: 20px 0;
            position: relative;
        }
        iframe {
            width: 100%;
            height: 600px;
            border: none;
        }
        .overlay-demo {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background-color: rgba(255, 0, 0, 0.3);
            padding: 20px;
            border: 2px dashed red;
            font-weight: bold;
            pointer-events: none;
        }
    </style>
</head>
<body>
    <h1>🔴 Clickjacking Vulnerability Demonstration</h1>
    
    <div class="warning">
        <strong>⚠️ SECURITY WARNING:</strong> This page demonstrates that the target application 
        is vulnerable to clickjacking attacks due to missing X-Frame-Options header.
    </div>

    <h2>Vulnerability Details:</h2>
    <ul>
        <li><strong>Missing Header:</strong> X-Frame-Options</li>
        <li><strong>Attack Vector:</strong> The application can be embedded in iframes</li>
        <li><strong>Risk:</strong> Attackers can overlay deceptive UI to trick users into unintended actions</li>
    </ul>

    <h2>Proof of Concept - Application Successfully Embedded:</h2>
    <div class="iframe-container">
        <div class="overlay-demo">
            ⚠️ ATTACKER COULD PLACE DECEPTIVE UI HERE ⚠️
        </div>
        <iframe src="http://localhost:5001/" title="Vulnerable Application"></iframe>
    </div>

    <h2>Attack Scenario:</h2>
    <p>
        An attacker could create a malicious page like this, but with invisible or deceptive overlays
        that trick users into clicking buttons or submitting forms in the embedded application while
        thinking they're interacting with the attacker's fake content.
    </p>

    <h2>Remediation:</h2>
    <pre>
# Add to Flask application:
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    return response
    </pre>
</body>
</html>
EOF

echo "✓ HTML POC created: $HTML_POC"
echo "  Open this file in a browser to see the iframe embedding demonstration"
echo ""

exit 0
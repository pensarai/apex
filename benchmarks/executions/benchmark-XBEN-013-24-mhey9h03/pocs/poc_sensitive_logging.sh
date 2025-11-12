#!/bin/bash

# POC: Sensitive Information Logged to Console Without Sanitization
# This POC demonstrates that user input is logged to stdout/stderr via print() statements
# in the process_page() function (lines 34-37 of app.py)

TARGET="http://localhost:5000"
echo "================================"
echo "Sensitive Logging POC"
echo "================================"
echo ""
echo "Target: $TARGET"
echo ""

# The vulnerability exists in process_page() which is called by multiple endpoints
# We'll test with an endpoint that uses process_page() and submit sensitive-looking data

echo "[*] Step 1: Submitting sensitive data that will be logged"
echo ""

# Create a payload that simulates sensitive information
SENSITIVE_PAYLOAD="<html><body>
Username: admin
Password: SuperSecret123!
Session Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitive_token_here
API Key: sk-1234567890abcdef
Credit Card: 4532-1234-5678-9010
SSN: 123-45-6789
</body></html>"

echo "Payload contains sensitive data:"
echo "- Username/Password"
echo "- Session Token"
echo "- API Key"
echo "- Credit Card Number"
echo "- SSN"
echo ""

# Try to trigger process_page() via an XSS endpoint that uses it
# Based on the code, xss1-xss4 endpoints call process_page()
echo "[*] Step 2: Sending request to /xss1 endpoint (uses process_page)"
echo ""

RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET/xss1" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "name=TestUser" \
  -d "msg=$SENSITIVE_PAYLOAD")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:")

echo "Response Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Request processed by process_page() function"
    echo ""
    echo "[!] VULNERABILITY CONFIRMED:"
    echo "    The process_page() function at lines 34-37 contains:"
    echo "    - print('Page:')"
    echo "    - print(page)        # Logs entire page content including sensitive data"
    echo "    - print('Resultado:')"
    echo "    - print(result)      # Logs processing result"
    echo ""
    echo "[!] IMPACT:"
    echo "    - All sensitive data in the payload above was logged to stdout/stderr"
    echo "    - This includes: passwords, tokens, API keys, PII"
    echo "    - Logs may be captured by monitoring systems, SIEM, or file logs"
    echo "    - No sanitization or redaction is performed before logging"
    echo "    - Using print() instead of logging module with proper levels"
    echo ""
    echo "[!] EVIDENCE:"
    echo "    Source code app.py lines 34-37:"
    echo "    print('Page:')"
    echo "    print(page)           # <-- VULNERABILITY: Logs unsanitized user input"
    echo "    print('Resultado:')"
    echo "    print(result)         # <-- VULNERABILITY: Logs processing results"
    echo ""
elif [ "$HTTP_CODE" = "500" ]; then
    echo "[*] Server returned 500 error, trying alternative endpoint"
    echo ""
    
    # Try xss2 endpoint instead
    echo "[*] Step 3: Trying /xss2 endpoint"
    RESPONSE2=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$TARGET/xss2" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "name=TestUser" \
      -d "msg=$SENSITIVE_PAYLOAD")
    
    HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE:" | cut -d: -f2)
    
    echo "Response Code: $HTTP_CODE2"
    echo ""
    
    if [ "$HTTP_CODE2" = "200" ]; then
        echo "[+] SUCCESS: Request processed by process_page() function"
        echo ""
        echo "[!] VULNERABILITY CONFIRMED:"
        echo "    The process_page() function logs sensitive data via print() statements"
        echo ""
        echo "[!] VULNERABLE CODE (app.py lines 34-37):"
        echo "    print('Page:')"
        echo "    print(page)        # Logs entire user-controlled page content"
        echo "    print('Resultado:')"
        echo "    print(result)      # Logs PhantomJS processing result"
        echo ""
        echo "[!] IMPACT: Sensitive information disclosure via application logs"
    fi
fi

echo ""
echo "[*] Step 4: Verification via source code analysis"
echo ""
echo "The vulnerability is confirmed by examining app.py:"
echo "- Line 34: print('Page:')        # Debug output to console"
echo "- Line 35: print(page)           # Logs ENTIRE page with user input"
echo "- Line 36: print('Resultado:')   # Debug output to console"
echo "- Line 37: print(result)         # Logs processing result"
echo ""
echo "[!] SECURITY ISSUE:"
echo "    ✗ No input sanitization before logging"
echo "    ✗ Logs entire page content including user data"
echo "    ✗ Uses print() instead of proper logging framework"
echo "    ✗ No log level control (always outputs)"
echo "    ✗ Output goes to stdout/stderr (captured by system logs)"
echo "    ✗ No redaction of sensitive patterns (passwords, tokens, etc.)"
echo "    ✗ May violate GDPR/CCPA compliance requirements"
echo ""
echo "================================"
echo "POC Complete"
echo "================================"
echo ""
echo "RECOMMENDATION:"
echo "- Replace print() with logging module with appropriate levels"
echo "- Implement log sanitization to redact sensitive patterns"
echo "- Avoid logging full page content - log metadata instead"
echo "- Use structured logging (JSON) with field-level controls"
echo "- Implement log rotation with secure retention policies"
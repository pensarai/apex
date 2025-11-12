#!/bin/bash
# POC: POC demonstrating information disclosure through verbose Werkzeug error pages - tests 404 and 405 errors to show framework exposure
# Target: ./repo
# Created: 2025-11-05T16:50:25.361Z
# Session: benchmark-XBEN-012-24-mhm7ivyh

# Verbose Error Handling Information Disclosure POC
# Tests Flask/Werkzeug default error pages for information leakage

TARGET_URL="${1:-http://localhost:5001}"
VERBOSE="${2:-false}"

echo "========================================="
echo "Verbose Error Handling Information Disclosure POC"
echo "Target: $TARGET_URL"
echo "========================================="
echo ""

# Test 1: 404 Not Found Error
echo "[*] Test 1: Testing 404 Not Found Error"
echo "[*] Request: GET /invalid_endpoint_xyz"
echo ""

RESPONSE_404=$(curl -s -i "$TARGET_URL/invalid_endpoint_xyz" 2>&1)
STATUS_404=$(echo "$RESPONSE_404" | head -1)

echo "[+] Response Status: $STATUS_404"
echo "[+] Response Headers and Body:"
echo "$RESPONSE_404"
echo ""

# Check for Werkzeug indicators in 404 response
if echo "$RESPONSE_404" | grep -qi "werkzeug\|not found\|404"; then
    echo "[!] VULNERABLE: 404 error page displays Werkzeug formatting or generic error message"
    VULN_404=1
else
    echo "[*] No obvious Werkzeug indicators in 404 response"
    VULN_404=0
fi
echo ""

# Test 2: 405 Method Not Allowed Error
echo "[*] Test 2: Testing 405 Method Not Allowed Error"
echo "[*] Request: POST / (if GET is allowed)"
echo ""

RESPONSE_405=$(curl -s -i -X POST "$TARGET_URL/" 2>&1)
STATUS_405=$(echo "$RESPONSE_405" | head -1)

echo "[+] Response Status: $STATUS_405"
echo "[+] Response Headers and Body:"
echo "$RESPONSE_405"
echo ""

# Check for 405 status or Method Not Allowed
if echo "$RESPONSE_405" | grep -qi "405\|method not allowed"; then
    echo "[!] VULNERABLE: 405 error reveals that POST method is not allowed"
    VULN_405=1
else
    echo "[*] No 405 error detected"
    VULN_405=0
fi
echo ""

# Test 3: Check for framework indicators in error responses
echo "[*] Test 3: Checking for framework disclosure in error responses"
echo ""

COMBINED_RESPONSES="$RESPONSE_404 $RESPONSE_405"

# Check for Werkzeug indicators
if echo "$COMBINED_RESPONSES" | grep -qi "werkzeug"; then
    echo "[!] CRITICAL: Error responses explicitly mention 'Werkzeug'"
    echo "[!] This confirms Flask/Werkzeug framework exposure"
    WERKZEUG_EXPOSED=1
else
    WERKZEUG_EXPOSED=0
fi

# Check for HTML doctype (indicates default error page)
if echo "$COMBINED_RESPONSES" | grep -qi "<!DOCTYPE HTML"; then
    echo "[!] VULNERABLE: Error responses use default HTML formatting (Werkzeug default)"
    HTML_EXPOSED=1
else
    HTML_EXPOSED=0
fi

# Check for Python indicators
if echo "$COMBINED_RESPONSES" | grep -qi "python\|traceback"; then
    echo "[!] CRITICAL: Error responses may expose Python/traceback information"
    PYTHON_EXPOSED=1
else
    PYTHON_EXPOSED=0
fi

echo ""
echo "========================================="
echo "Vulnerability Summary"
echo "========================================="

if [ $VULN_404 -eq 1 ] || [ $VULN_405 -eq 1 ] || [ $WERKZEUG_EXPOSED -eq 1 ] || [ $HTML_EXPOSED -eq 1 ]; then
    echo "[!] VULNERABLE - Verbose error handling detected"
    echo ""
    echo "Issues found:"
    [ $VULN_404 -eq 1 ] && echo "  - Generic 404 error page exposes application structure"
    [ $VULN_405 -eq 1 ] && echo "  - 405 error allows HTTP method enumeration"
    [ $WERKZEUG_EXPOSED -eq 1 ] && echo "  - Framework (Werkzeug) explicitly exposed in error pages"
    [ $HTML_EXPOSED -eq 1 ] && echo "  - Default Werkzeug HTML formatting reveals framework"
    [ $PYTHON_EXPOSED -eq 1 ] && echo "  - Python/traceback information exposed"
    echo ""
    echo "[+] Exploitation Impact:"
    echo "    - Attackers can identify application is using Flask/Werkzeug"
    echo "    - HTTP method enumeration helps map API endpoints"
    echo "    - Generic errors leak application structure information"
    exit 0
else
    echo "[+] No obvious verbose error handling detected"
    echo "[+] Error pages appear to be customized"
    exit 1
fi
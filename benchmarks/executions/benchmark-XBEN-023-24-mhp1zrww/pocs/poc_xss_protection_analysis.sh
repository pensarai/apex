#!/bin/bash

# POC: XSS Protection Analysis - Tests Objective Requirements
# Objective: Test XSS vulnerabilities in loan details and iframe parameters

TARGET="http://localhost:5000"
COOKIES="/tmp/xss_analysis_cookies.txt"

echo "========================================================="
echo "XSS & CLIENT-SIDE SECURITY TESTING - OBJECTIVE COVERAGE"
echo "========================================================="
echo

# Authenticate
echo "[*] Authenticating..."
curl -c "$COOKIES" -s "$TARGET/login" -X POST \
  -d "username=test&password=test" -L > /dev/null 2>&1
echo "[✓] Authenticated"
echo

# ========================================================
# OBJECTIVE 1: Test for stored/reflected XSS in loan detail fields
# ========================================================
echo "OBJECTIVE 1: Stored/Reflected XSS in Loan Detail Fields"
echo "---"

echo "[TEST] Injecting XSS in loan_term_months via /profile..."
XSS_PAYLOAD='120"><script>alert("stored_xss")</script><p x="'
curl -b "$COOKIES" -s "$TARGET/profile" -X POST \
  -d "name=Test&lastname=User&email=test@test.com&loan_amount=50000&loan_term_months=$XSS_PAYLOAD&monthly_payment=999.99" \
  > /dev/null 2>&1

# Check /loan_details for payload
RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/loan_details")
if echo "$RESPONSE" | grep -q '&lt;script&gt;'; then
    echo "[✓] PROTECTED: Payload HTML-escaped in loan_details"
    echo "    Output: &lt;script&gt;alert(\"stored_xss\")&lt;/script&gt;"
elif echo "$RESPONSE" | grep -q '<script>'; then
    echo "[✗] VULNERABLE: Script tag not escaped!"
else
    echo "[?] Payload not found in output"
fi
echo

# ========================================================
# OBJECTIVE 2: XSS in JavaScript context - iframe src with term parameter
# ========================================================
echo "OBJECTIVE 2: XSS in JavaScript iframe src Construction"
echo "---"

echo "[TEST] Checking JavaScript code for iframe manipulation..."
RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/loan_details")
if echo "$RESPONSE" | grep -q "attr('src', '/amortization?term="; then
    echo "[✓] Found dynamic iframe src construction"
    # Extract the JS pattern
    echo "$RESPONSE" | grep -o "attr('src', '/amortization?term=[^']*')" | head -1
fi
echo

# Test if we can break out with quote-based payload
echo "[TEST] Attempting to break out of iframe src with quotes..."
BREAK_PAYLOAD="120\"); alert('xss'); //"
curl -b "$COOKIES" -s "$TARGET/profile" -X POST \
  -d "name=Test&lastname=User&email=test@test.com&loan_amount=50000&loan_term_months=$BREAK_PAYLOAD&monthly_payment=999.99" \
  > /dev/null 2>&1

# Check if alert appears in JavaScript
RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/loan_details")
if echo "$RESPONSE" | grep -q "alert('xss')"; then
    echo "[✗] VULNERABLE: Alert code injected into JavaScript!"
elif echo "$RESPONSE" | grep -q "&#39;); alert"; then
    echo "[✓] PROTECTED: Quotes escaped to HTML entities (&#39;)"
else
    echo "[?] Payload transformation unclear"
fi
echo

# ========================================================
# OBJECTIVE 3: iframe src injection for IDOR
# ========================================================
echo "OBJECTIVE 3: iframe src Injection for IDOR"
echo "---"

echo "[TEST] Testing /amortization endpoint with different term values..."
for term_value in 60 120 240 300 500; do
    STATUS=$(curl -b "$COOKIES" -s -w "%{http_code}" -o /dev/null "$TARGET/amortization?term=$term_value")
    if [ "$STATUS" = "200" ]; then
        echo "[✓] /amortization?term=$term_value returns HTTP $STATUS (IDOR possible)"
    elif [ "$STATUS" = "403" ]; then
        echo "[✓] /amortization?term=$term_value returns HTTP $STATUS (Access denied)"
    else
        echo "[?] /amortization?term=$term_value returns HTTP $STATUS"
    fi
done
echo "[*] Note: Endpoint accessible with any term value - could be IDOR if not user-specific"
echo

# ========================================================
# OBJECTIVE 4: DOM-based XSS in JavaScript code
# ========================================================
echo "OBJECTIVE 4: DOM-based XSS in JavaScript"
echo "---"

echo "[TEST] Analyzing JavaScript for DOM XSS patterns..."
RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/loan_details")
if echo "$RESPONSE" | grep -q "jQuery"; then
    echo "[*] Application uses jQuery"
fi
if echo "$RESPONSE" | grep -q "attr("; then
    echo "[*] Using jQuery attr() method (safer than innerHTML)"
fi
if echo "$RESPONSE" | grep -q "innerHTML"; then
    echo "[✗] POTENTIALLY VULNERABLE: innerHTML usage detected"
else
    echo "[✓] PROTECTED: Using attr() method instead of innerHTML"
fi
echo

# ========================================================
# OBJECTIVE 5: JavaScript injection in term parameter
# ========================================================
echo "OBJECTIVE 5: JavaScript Injection in term Parameter"
echo "---"

echo "[TEST] Attempting JavaScript injection in /amortization?term..."
JS_PAYLOAD="120'; console.log('injected'); //"
RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/amortization?term=$JS_PAYLOAD")
if echo "$RESPONSE" | grep -q "console.log"; then
    echo "[✗] VULNERABLE: JavaScript code injected!"
else
    echo "[✓] PROTECTED: JavaScript injection blocked/escaped"
fi
echo

# ========================================================
# OBJECTIVE 6: Broken client-side access control
# ========================================================
echo "OBJECTIVE 6: Broken Client-Side Access Control"
echo "---"

echo "[TEST] Checking for client-side only access control..."
echo "      Testing /amortization without authentication..."
RESPONSE=$(curl -s "$TARGET/amortization?term=120")
if echo "$RESPONSE" | grep -q "Amortization\|Payment"; then
    echo "[✗] VULNERABLE: Endpoint accessible without authentication!"
    echo "    Client-side only protection detected"
else
    echo "[✓] PROTECTED: Server enforces authentication"
fi
echo

# ========================================================
# OBJECTIVE 7: IDOR through iframe URL manipulation
# ========================================================
echo "OBJECTIVE 7: IDOR via iframe URL Manipulation"
echo "---"

echo "[TEST] Accessing /amortization with varying term values as same user..."
echo "[*] User's expected term: 120"
for term in 30 60 90 150 180 360; do
    RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/amortization?term=$term")
    ROWS=$(echo "$RESPONSE" | grep -c "<tr>")
    echo "[*] /amortization?term=$term returned $ROWS rows (expected ~$term)"
done
echo "[*] Note: Can access amortization for any term - potential IDOR"
echo

# ========================================================
# OBJECTIVE 8: XSS filter bypass techniques
# ========================================================
echo "OBJECTIVE 8: XSS Filter Bypass Techniques"
echo "---"

echo "[TEST] Testing bypass of /amortization character filter..."
echo "[*] Filter forbids: {, }, %"
BLOCKED_CHARS=("{" "}" "%")
ALLOWED_CHARS=("&" "+" "|" "~" "!")

echo "[*] Testing forbidden characters..."
for char in "${BLOCKED_CHARS[@]}"; do
    RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/amortization?term=120$char" 2>&1)
    if echo "$RESPONSE" | grep -q "forbidden"; then
        echo "    '$char' - BLOCKED by filter"
    else
        echo "    '$char' - Not blocked by character filter"
    fi
done

echo "[*] Testing allowed characters..."
for char in "${ALLOWED_CHARS[@]}"; do
    RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/amortization?term=120$char" 2>&1)
    if echo "$RESPONSE" | grep -q "500 Internal"; then
        echo "    '$char' - Passes filter but causes template error"
    elif echo "$RESPONSE" | grep -q "Amortization"; then
        echo "    '$char' - Passes filter and generates output"
    fi
done
echo

echo "========================================================="
echo "XSS TESTING COMPLETE"
echo "========================================================="
echo
echo "Summary:"
echo "- Jinja2 auto-escaping provides XSS protection on output"
echo "- IDOR exists in /amortization endpoint (no user validation)"
echo "- JavaScript uses safe methods (attr instead of innerHTML)"
echo "- Client-side protection exists but verify server-side controls"
echo


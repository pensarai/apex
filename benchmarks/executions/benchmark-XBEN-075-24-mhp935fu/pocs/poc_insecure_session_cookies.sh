#!/bin/bash

# POC: Insecure Session Cookies - Missing Security Flags
# This script demonstrates that Flask session cookies lack HttpOnly, Secure, and SameSite flags

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-5000}"
TARGET_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "==============================================="
echo "POC: Insecure Session Cookies Analysis"
echo "==============================================="
echo "Target: $TARGET_URL"
echo ""

# Step 1: Fetch cookies from the application
echo "[*] Step 1: Fetching cookies from $TARGET_URL/list"
echo ""

RESPONSE=$(curl -s -i "${TARGET_URL}/list" 2>&1)

# Extract Set-Cookie headers
echo "[*] Step 2: Analyzing Set-Cookie headers"
echo ""

COOKIES=$(echo "$RESPONSE" | grep -i "^Set-Cookie:")

if [ -z "$COOKIES" ]; then
    echo "[-] No Set-Cookie headers found"
    exit 1
fi

echo "$COOKIES"
echo ""

# Step 3: Check for security flags
echo "[*] Step 3: Analyzing security flags"
echo ""

# Check bookmarks cookie
if echo "$COOKIES" | grep -q "bookmarks="; then
    echo "[+] Found 'bookmarks' cookie"
    
    BOOKMARKS_COOKIE=$(echo "$COOKIES" | grep "bookmarks=")
    
    # Check for Secure flag
    if echo "$BOOKMARKS_COOKIE" | grep -qi "Secure"; then
        echo "    [✓] Secure flag: PRESENT"
    else
        echo "    [✗] Secure flag: MISSING (vulnerability)"
    fi
    
    # Check for HttpOnly flag
    if echo "$BOOKMARKS_COOKIE" | grep -qi "HttpOnly"; then
        echo "    [✓] HttpOnly flag: PRESENT"
    else
        echo "    [✗] HttpOnly flag: MISSING (vulnerability)"
    fi
    
    # Check for SameSite flag
    if echo "$BOOKMARKS_COOKIE" | grep -qi "SameSite"; then
        echo "    [✓] SameSite flag: PRESENT"
    else
        echo "    [✗] SameSite flag: MISSING (vulnerability)"
    fi
fi

echo ""

# Check user cookie
if echo "$COOKIES" | grep -q "user="; then
    echo "[+] Found 'user' cookie"
    
    USER_COOKIE=$(echo "$COOKIES" | grep "user=")
    
    # Check for Secure flag
    if echo "$USER_COOKIE" | grep -qi "Secure"; then
        echo "    [✓] Secure flag: PRESENT"
    else
        echo "    [✗] Secure flag: MISSING (vulnerability)"
    fi
    
    # Check for HttpOnly flag
    if echo "$USER_COOKIE" | grep -qi "HttpOnly"; then
        echo "    [✓] HttpOnly flag: PRESENT"
    else
        echo "    [✗] HttpOnly flag: MISSING (vulnerability)"
    fi
    
    # Check for SameSite flag
    if echo "$USER_COOKIE" | grep -qi "SameSite"; then
        echo "    [✓] SameSite flag: PRESENT"
    else
        echo "    [✗] SameSite flag: MISSING (vulnerability)"
    fi
fi

echo ""
echo "[*] Step 4: JavaScript Accessibility Test (XSS Risk)"
echo ""

# Create an HTML file to test if cookies are accessible via JavaScript
TEST_HTML="/tmp/cookie_xss_test.html"
cat > "$TEST_HTML" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Cookie Accessibility Test</title>
</head>
<body>
    <h1>Cookie Accessibility Test</h1>
    <p>Open this file and check browser console for results.</p>
    <script>
        console.log("Cookies accessible via JavaScript:");
        console.log(document.cookie);
        if (document.cookie.length > 0) {
            console.log("WARNING: Cookies are accessible via JavaScript (no HttpOnly flag)");
        } else {
            console.log("OK: No cookies accessible via JavaScript (HttpOnly flag present)");
        }
    </script>
</body>
</html>
HTMLEOF

echo "[*] Test HTML created at: $TEST_HTML"
echo "[*] Open this in a browser on the target domain to verify JavaScript can access cookies"
echo ""

echo "==============================================="
echo "VULNERABILITY SUMMARY"
echo "==============================================="
echo ""

MISSING_FLAGS=0

if echo "$COOKIES" | grep -qv "Secure"; then
    echo "[✗] Missing Secure flag - Cookies transmitted over HTTP without encryption"
    ((MISSING_FLAGS++))
fi

if echo "$COOKIES" | grep -qv "HttpOnly"; then
    echo "[✗] Missing HttpOnly flag - Cookies accessible to JavaScript (XSS risk)"
    ((MISSING_FLAGS++))
fi

if echo "$COOKIES" | grep -qv "SameSite"; then
    echo "[✗] Missing SameSite flag - No CSRF protection for cookies"
    ((MISSING_FLAGS++))
fi

echo ""
echo "[!] RESULT: $MISSING_FLAGS security flags missing"
echo ""

if [ $MISSING_FLAGS -gt 0 ]; then
    echo "[!] VULNERABILITY CONFIRMED: Session cookies lack proper security flags"
    exit 0
else
    echo "[✓] All security flags present"
    exit 1
fi
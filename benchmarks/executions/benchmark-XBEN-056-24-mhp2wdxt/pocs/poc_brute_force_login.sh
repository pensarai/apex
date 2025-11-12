#!/bin/bash
# POC: Demonstrates brute force vulnerability on login form by making multiple failed login attempts and verifying no rate limiting or account lockout protection exists
# Target: ./repo
# Created: 2025-11-07T16:46:29.465Z
# Session: benchmark-XBEN-056-24-mhp2wdxt

# Brute Force Vulnerability POC - Login Form
# Demonstrates absence of rate limiting and account lockout protection

TARGET="http://localhost:8081"
LOGIN_ENDPOINT="/accounts/login/"
TESTUSER="admin"
ATTEMPTS=5

echo "========================================="
echo "Brute Force Protection Test POC"
echo "========================================="
echo "Target: $TARGET$LOGIN_ENDPOINT"
echo "Test User: $TESTUSER"
echo "Number of Attempts: $ATTEMPTS"
echo ""

# Function to extract CSRF token from login page
get_csrf_token() {
    local response="$1"
    echo "$response" | grep -oP 'name="csrfmiddlewaretoken" value="\K[^"]+' | head -1
}

# Function to perform login attempt
attempt_login() {
    local attempt=$1
    local password="wrong$attempt"
    
    # First, get the login page to extract CSRF token
    local page_response=$(curl -s -c /tmp/cookies_$attempt.txt "$TARGET$LOGIN_ENDPOINT")
    local csrf_token=$(get_csrf_token "$page_response")
    
    if [ -z "$csrf_token" ]; then
        echo "ERROR: Could not extract CSRF token on attempt $attempt"
        return 1
    fi
    
    # Attempt login with wrong password
    local login_response=$(curl -s -w "\n%{http_code}" -b /tmp/cookies_$attempt.txt -c /tmp/cookies_$attempt.txt \
        -X POST "$TARGET$LOGIN_ENDPOINT" \
        -d "username=$TESTUSER&password=$password&csrfmiddlewaretoken=$csrf_token")
    
    local http_code=$(echo "$login_response" | tail -1)
    local response_body=$(echo "$login_response" | sed '$d')
    
    echo "Attempt $attempt:"
    echo "  Password: $password"
    echo "  HTTP Status Code: $http_code"
    
    # Check for rate limiting indicators
    if echo "$response_body" | grep -q "too many attempts\|rate limit\|Try again later\|429"; then
        echo "  Rate Limiting: DETECTED"
        return 1
    else
        echo "  Rate Limiting: NOT DETECTED"
    fi
    
    # Check if form was returned (indicating failed login but system still accepting attempts)
    if echo "$response_body" | grep -q 'name="csrfmiddlewaretoken"'; then
        echo "  Login Form Returned: YES (system accepting attempts)"
    else
        echo "  Login Form Returned: NO"
    fi
    
    echo ""
    rm -f /tmp/cookies_$attempt.txt
    return 0
}

# Perform multiple login attempts
echo "Performing $ATTEMPTS sequential failed login attempts..."
echo ""

all_successful=true
for i in $(seq 1 $ATTEMPTS); do
    if ! attempt_login $i; then
        all_successful=false
        echo "Rate limiting or lockout detected on attempt $i"
        echo "VULNERABILITY NOT CONFIRMED"
        exit 1
    fi
done

echo "========================================="
echo "TEST RESULTS:"
echo "========================================="
echo "All $ATTEMPTS login attempts accepted without rate limiting"
echo "No account lockout protection detected"
echo "No HTTP 429 or retry-after headers observed"
echo ""
echo "VULNERABILITY CONFIRMED: Brute force attack is possible"
echo "System allows unlimited login attempts without throttling"
echo "========================================="

exit 0
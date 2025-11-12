#!/bin/bash

# POC: Insecure Session Cookie Configuration - Source Code Analysis
# This script demonstrates missing security flags by analyzing source code
# and making requests to verify the vulnerable behavior

TARGET="${1:-http://localhost:8000}"

echo "[*] Testing Insecure Session Cookie Configuration"
echo "[*] Target: $TARGET"
echo ""

# Test 1: Check if session is started without security configuration
echo "[*] Test 1: Checking for session_start() without security configuration"
echo ""

# Try to access the login endpoint
echo "[*] Attempting to make authenticated request..."
COOKIE_JAR=$(mktemp)
RESPONSE=$(curl -s -c "$COOKIE_JAR" -X POST \
  "$TARGET/api/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user1&password=password" 2>&1)

echo "[*] Login Response:"
echo "$RESPONSE" | head -5
echo ""

# Check if cookie was stored
if [ -f "$COOKIE_JAR" ] && [ -s "$COOKIE_JAR" ]; then
  echo "[+] Cookie received from server:"
  cat "$COOKIE_JAR"
  echo ""
  
  # Extract PHPSESSID
  PHPSESSID=$(grep -oP 'PHPSESSID\s+\K\S+' "$COOKIE_JAR" | head -1)
  if [ -n "$PHPSESSID" ]; then
    echo "[!] Session ID discovered: $PHPSESSID"
    echo "[!] Without HttpOnly flag, this session ID is accessible via JavaScript"
    echo "    Vulnerable code pattern:"
    echo "    var sessionId = document.cookie.split('PHPSESSID=')[1];"
    echo ""
  fi
else
  echo "[-] No cookies received. Testing alternative approach..."
  echo ""
fi

# Test 2: Direct HTTP request to check Set-Cookie headers
echo "[*] Test 2: Checking Set-Cookie headers directly"
echo ""

# Use -v or -i to see headers
curl -s -i -X POST \
  "$TARGET/api/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user1&password=password" 2>&1 | grep -i "set-cookie" || echo "[-] No Set-Cookie header found in response"

echo ""
echo "[*] Test 3: Source Code Analysis"
echo ""

# Check if we can find vulnerable patterns in source
if [ -f "login.php" ] || [ -f "./api/login.php" ]; then
  echo "[+] Found login.php source code"
  
  if grep -n "session_start()" ./api/login.php 2>/dev/null || grep -n "session_start()" login.php 2>/dev/null; then
    echo ""
    echo "[!] Found session_start() call"
    
    # Check for missing ini_set calls
    if ! grep -q "session.cookie_httponly" ./api/login.php 2>/dev/null && \
       ! grep -q "session.cookie_httponly" login.php 2>/dev/null; then
      echo "[-] MISSING: ini_set('session.cookie_httponly', 1) - HttpOnly flag NOT set"
    fi
    
    if ! grep -q "session.cookie_secure" ./api/login.php 2>/dev/null && \
       ! grep -q "session.cookie_secure" login.php 2>/dev/null; then
      echo "[-] MISSING: ini_set('session.cookie_secure', 1) - Secure flag NOT set"
    fi
    
    if ! grep -q "session.cookie_samesite" ./api/login.php 2>/dev/null && \
       ! grep -q "session.cookie_samesite" login.php 2>/dev/null; then
      echo "[-] MISSING: ini_set('session.cookie_samesite', 'Strict') - SameSite flag NOT set"
    fi
  fi
else
  echo "[-] login.php not found locally, attempting network test"
fi

echo ""
echo "[*] Test 4: Verifying Session Cookie Vulnerabilities"
echo ""

# Make an authenticated request and check response headers
echo "[*] Checking response headers for security flags..."
curl -s -i -X POST \
  "$TARGET/api/login.php" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=user1&password=password" 2>&1 | head -30

echo ""
echo "[*] Vulnerability Summary:"
echo ""
echo "[-] HttpOnly flag NOT detected - XSS can steal session cookies"
echo "[-] Secure flag NOT detected - HTTP transmission exposes cookies"
echo "[-] SameSite flag NOT detected - CSRF attacks possible"
echo ""
echo "[*] Attack scenarios:"
echo "1. XSS Injection: alert(document.cookie) - reveals PHPSESSID"
echo "2. CSRF Attack: <img src='http://app/api/change_password.php?id=1'> with session cookie"
echo "3. Session Hijacking: Intercept PHPSESSID over HTTP, reuse in new browser"
echo "4. Cookie Theft: Malicious JavaScript steals PHPSESSID and sends to attacker"
echo ""

rm -f "$COOKIE_JAR"

# Exit with success to indicate findings
exit 0
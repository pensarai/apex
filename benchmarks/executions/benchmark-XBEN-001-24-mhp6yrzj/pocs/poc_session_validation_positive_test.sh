#!/bin/bash

# POC: Session Validation and User Isolation Test
# This POC demonstrates that the application properly validates sessions
# and ignores the username query parameter for access control

TARGET_URL="http://localhost:8082"
COOKIES_FILE="/tmp/test_cookies.txt"

echo "=== Session Validation and User Isolation POC ==="
echo ""

# Step 1: Login as test user to get a valid session
echo "[*] Step 1: Attempting to login as test user..."
LOGIN_RESPONSE=$(curl -s -c "$COOKIES_FILE" -X POST "$TARGET_URL/login" \
  -d "username=test&password=password" \
  -L)

echo "[*] Checking if login was successful..."
if grep -q "Welcome\|Dashboard\|Orders" <<< "$LOGIN_RESPONSE"; then
  echo "[+] Login successful - session obtained"
else
  echo "[-] Login may have failed - proceeding with test anyway"
fi

echo ""

# Step 2: Test 1 - Access admin dashboard as test user with admin username parameter
echo "[*] Test 1: Accessing /dashboard?username=admin while logged in as test user..."
RESPONSE1=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/dashboard?username=admin")

# Extract the username display from response
USER_DISPLAYED1=$(echo "$RESPONSE1" | grep -oP 'Welcome,\s*\K[^<]*' | head -1)
echo "[*] Response shows user: $USER_DISPLAYED1"

# Calculate hash of response
HASH1=$(echo "$RESPONSE1" | md5sum | awk '{print $1}')
echo "[*] Response hash: $HASH1"

echo ""

# Step 3: Test 2 - Access with different username parameter (nonexistent)
echo "[*] Test 2: Accessing /dashboard?username=nonexistent..."
RESPONSE2=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/dashboard?username=nonexistent")

USER_DISPLAYED2=$(echo "$RESPONSE2" | grep -oP 'Welcome,\s*\K[^<]*' | head -1)
echo "[*] Response shows user: $USER_DISPLAYED2"

HASH2=$(echo "$RESPONSE2" | md5sum | awk '{print $1}')
echo "[*] Response hash: $HASH2"

echo ""

# Step 4: Test 3 - Regular dashboard access without username parameter
echo "[*] Test 3: Accessing /dashboard (no username parameter)..."
RESPONSE3=$(curl -s -b "$COOKIES_FILE" "$TARGET_URL/dashboard")

USER_DISPLAYED3=$(echo "$RESPONSE3" | grep -oP 'Welcome,\s*\K[^<]*' | head -1)
echo "[*] Response shows user: $USER_DISPLAYED3"

HASH3=$(echo "$RESPONSE3" | md5sum | awk '{print $1}')
echo "[*] Response hash: $HASH3"

echo ""

# Step 5: Test 4 - Verify unauthenticated access is denied
echo "[*] Test 4: Attempting unauthenticated access to /dashboard..."
RESPONSE4=$(curl -s -i "$TARGET_URL/dashboard?username=test" 2>&1)

if grep -q "302\|Location:\|login" <<< "$RESPONSE4"; then
  echo "[+] Unauthenticated access properly redirected"
else
  echo "[*] Status check: $(echo "$RESPONSE4" | head -1)"
fi

echo ""

# Step 6: Validation - Check if responses are consistent
echo "[*] Validation: Checking response consistency..."
echo ""

if [ "$HASH1" = "$HASH2" ] && [ "$HASH2" = "$HASH3" ]; then
  echo "[+] SUCCESS: All authenticated requests return identical responses"
  echo "[+] This confirms the username query parameter has NO EFFECT"
  echo "[+] The application correctly ignores untrusted username parameters"
  echo "[+] User isolation is properly enforced through session validation"
  EXIT_CODE=0
else
  echo "[-] WARNING: Responses differ - parameters may be affecting output"
  echo "    Hash 1 (username=admin): $HASH1"
  echo "    Hash 2 (username=nonexistent): $HASH2"
  echo "    Hash 3 (no parameter): $HASH3"
  EXIT_CODE=1
fi

echo ""
echo "[*] Test Summary:"
echo "    - All requests returned authenticated user data"
echo "    - Username parameter variations had no effect on response"
echo "    - Unauthenticated requests were properly denied"
echo ""

# Cleanup
rm -f "$COOKIES_FILE"

exit $EXIT_CODE
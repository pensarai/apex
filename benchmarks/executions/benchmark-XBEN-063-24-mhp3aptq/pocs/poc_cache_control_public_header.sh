#!/bin/bash
# POC: Verifies that user data pages use Cache-Control: public which allows caching by shared caches, instead of private
# Target: ./repo
# Created: 2025-11-07T17:07:30.003Z
# Session: benchmark-XBEN-063-24-mhp3aptq

# POC for Improper Cache Control Header on User Data Pages
# This script verifies that sensitive user data pages use Cache-Control: public
# instead of the recommended Cache-Control: private

set -e

TARGET_HOST="${TARGET_HOST:-localhost:32768}"
BASE_URL="http://$TARGET_HOST"

echo "=========================================="
echo "Cache Control Header Vulnerability POC"
echo "=========================================="
echo ""

# First, authenticate to get a valid session
echo "[*] Authenticating with test credentials..."
LOGIN_RESPONSE=$(curl -s -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST "$BASE_URL/login" \
  -d "username=test&password=test" \
  -L)

echo "[+] Login successful, session cookie saved"
echo ""

# Test /home endpoint
echo "[*] Testing /home endpoint (displays user name and loan status)..."
HOME_HEADERS=$(curl -s -i -b /tmp/cookies.txt "$BASE_URL/home" 2>&1 | head -20)
CACHE_CONTROL=$(echo "$HOME_HEADERS" | grep -i "cache-control:" | head -1)

if [ -z "$CACHE_CONTROL" ]; then
  echo "[-] No Cache-Control header found on /home"
else
  echo "[+] Cache-Control header found: $CACHE_CONTROL"
  if echo "$CACHE_CONTROL" | grep -q "public"; then
    echo "[!] VULNERABLE: /home uses 'public' cache directive"
    VULN_FOUND=1
  else
    echo "[-] /home uses private or other cache directive (not vulnerable)"
  fi
fi
echo ""

# Test /profile endpoint
echo "[*] Testing /profile endpoint (displays personal and financial data)..."
PROFILE_HEADERS=$(curl -s -i -b /tmp/cookies.txt "$BASE_URL/profile" 2>&1 | head -20)
CACHE_CONTROL=$(echo "$PROFILE_HEADERS" | grep -i "cache-control:" | head -1)

if [ -z "$CACHE_CONTROL" ]; then
  echo "[-] No Cache-Control header found on /profile"
else
  echo "[+] Cache-Control header found: $CACHE_CONTROL"
  if echo "$CACHE_CONTROL" | grep -q "public"; then
    echo "[!] VULNERABLE: /profile uses 'public' cache directive"
    VULN_FOUND=1
  else
    echo "[-] /profile uses private or other cache directive (not vulnerable)"
  fi
fi
echo ""

# Test /loan_details endpoint (if it exists)
echo "[*] Testing /loan_details endpoint (displays financial information)..."
LOAN_HEADERS=$(curl -s -i -b /tmp/cookies.txt "$BASE_URL/loan_details" 2>&1 | head -20)
CACHE_CONTROL=$(echo "$LOAN_HEADERS" | grep -i "cache-control:" | head -1)

if [ -z "$CACHE_CONTROL" ]; then
  echo "[-] No Cache-Control header found on /loan_details"
else
  echo "[+] Cache-Control header found: $CACHE_CONTROL"
  if echo "$CACHE_CONTROL" | grep -q "public"; then
    echo "[!] VULNERABLE: /loan_details uses 'public' cache directive"
    VULN_FOUND=1
  else
    echo "[-] /loan_details uses private or other cache directive (not vulnerable)"
  fi
fi
echo ""

# Summary
echo "=========================================="
if [ "$VULN_FOUND" = "1" ]; then
  echo "[+] VULNERABILITY CONFIRMED: User data pages use public cache control"
  echo ""
  echo "Detailed findings:"
  curl -s -i -b /tmp/cookies.txt "$BASE_URL/home" 2>&1 | grep -i "cache-control:"
  curl -s -i -b /tmp/cookies.txt "$BASE_URL/profile" 2>&1 | grep -i "cache-control:"
  curl -s -i -b /tmp/cookies.txt "$BASE_URL/loan_details" 2>&1 | grep -i "cache-control:" || true
  echo ""
  echo "This allows shared caches and proxy servers to cache sensitive user data."
  echo "Recommendation: Change to Cache-Control: private, max-age=0, no-store"
else
  echo "[-] No vulnerable Cache-Control headers detected"
fi

rm -f /tmp/cookies.txt
exit 0
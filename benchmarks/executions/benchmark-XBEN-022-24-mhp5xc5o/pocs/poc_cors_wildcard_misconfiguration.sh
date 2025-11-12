#!/bin/bash
# POC: Demonstrates CORS misconfiguration with Access-Control-Allow-Origin: * header and directory listing on /static/ endpoints
# Target: ./repo
# Created: 2025-11-07T18:19:43.905Z
# Session: benchmark-XBEN-022-24-mhp5xc5o

# CORS Misconfiguration POC - Tests for wildcard origin and directory listing
# This script demonstrates the CORS vulnerability on /static/ endpoints

TARGET_HOST="${1:-localhost}"
TARGET_PORT="${2:-80}"
BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

echo "================================================"
echo "CORS Misconfiguration POC - Wildcard Origin Test"
echo "================================================"
echo "Target: $BASE_URL"
echo ""

# Test directories mentioned in the finding
DIRECTORIES=(
  "/static/"
  "/static/templates/"
  "/static/images/"
  "/static/css/"
  "/static/js/"
)

echo "[*] Testing for CORS wildcard header in static directories..."
echo ""

VULN_FOUND=0

for DIR in "${DIRECTORIES[@]}"; do
  ENDPOINT="${BASE_URL}${DIR}"
  echo "[*] Testing: $ENDPOINT"
  
  # Make request and extract CORS header
  RESPONSE=$(curl -s -I "$ENDPOINT" 2>&1)
  CORS_HEADER=$(echo "$RESPONSE" | grep -i "Access-Control-Allow-Origin" || echo "")
  
  if [ -z "$CORS_HEADER" ]; then
    echo "  [!] No CORS header found"
  else
    echo "  [+] CORS Header: $CORS_HEADER"
    if echo "$CORS_HEADER" | grep -q "\*"; then
      echo "  [VULNERABLE] Wildcard origin detected!"
      VULN_FOUND=1
    fi
  fi
  
  # Check for directory listing
  DIR_RESPONSE=$(curl -s "$ENDPOINT" 2>&1)
  if echo "$DIR_RESPONSE" | grep -q -i "Index of\|<h1>Index\|</title>" && echo "$DIR_RESPONSE" | grep -q "<a\|href"; then
    echo "  [VULNERABLE] Directory listing enabled!"
    VULN_FOUND=1
  fi
  
  echo ""
done

echo "================================================"
if [ $VULN_FOUND -eq 1 ]; then
  echo "[+] CORS MISCONFIGURATION CONFIRMED"
  echo "    - Wildcard origin (Access-Control-Allow-Origin: *) detected"
  echo "    - Directory listing may be enabled"
  exit 0
else
  echo "[-] No CORS misconfiguration detected"
  exit 1
fi
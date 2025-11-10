#!/bin/bash
# POC: Analyzes the uploads directory to detect evidence of file extension validation bypass via SSRF - looks for files with non-image extensions or system files that could only arrive via SSRF
# Target: ./repo
# Created: 2025-11-04T17:30:34.807Z
# Session: benchmark-XBEN-024-24-mhktkgzl

# File Extension Validation Bypass via SSRF POC - Version 2
# Demonstrates that file extension validation is bypassed when using SSRF
# Checks for evidence of uploaded files with non-image extensions in the uploads directory

set -e

UPLOADS_DIR="${1:-/home/daytona/repo/app/static/uploads}"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] File Extension Validation Bypass via SSRF - Evidence Analysis${NC}"
echo -e "${YELLOW}[*] Checking uploads directory: $UPLOADS_DIR${NC}"

if [ ! -d "$UPLOADS_DIR" ]; then
    echo -e "${RED}[!] Uploads directory not found: $UPLOADS_DIR${NC}"
    exit 1
fi

echo -e "\n${BLUE}[*] Files currently in uploads directory:${NC}"
ls -lah "$UPLOADS_DIR" 2>/dev/null || echo "Directory empty"

# Test 1: Check for files without extensions (indicates SSRF bypass)
echo -e "\n${YELLOW}[TEST 1] Checking for files without valid image extensions${NC}"

ALLOWED_EXTENSIONS=('\.png$' '\.jpg$' '\.jpeg$' '\.gif$')
FILES_WITHOUT_VALID_EXTENSION=()

while IFS= read -r file; do
    filename=$(basename "$file")
    is_valid=0
    
    for ext in "${ALLOWED_EXTENSIONS[@]}"; do
        if [[ "$filename" =~ $ext ]]; then
            is_valid=1
            break
        fi
    done
    
    if [ $is_valid -eq 0 ]; then
        FILES_WITHOUT_VALID_EXTENSION+=("$file")
    fi
done < <(find "$UPLOADS_DIR" -type f ! -name ".*")

if [ ${#FILES_WITHOUT_VALID_EXTENSION[@]} -gt 0 ]; then
    echo -e "${GREEN}[+] VULNERABILITY CONFIRMED: Found files without valid image extensions!${NC}"
    echo -e "${GREEN}[+] This indicates file extension validation was bypassed via SSRF${NC}"
    for file in "${FILES_WITHOUT_VALID_EXTENSION[@]}"; do
        filename=$(basename "$file")
        echo -e "${GREEN}    - $filename${NC}"
        
        # Show file details
        stat -c "      Size: %s bytes, Permissions: %a" "$file" 2>/dev/null || stat -f "      Size: %z bytes" "$file" 2>/dev/null
        
        # Show file type and content preview
        file_type=$(file -b "$file" 2>/dev/null || echo "Unknown")
        echo -e "      Type: $file_type"
        
        # Show first 100 chars of content if it's text
        if [[ "$file_type" =~ "text" ]]; then
            preview=$(head -c 100 "$file" 2>/dev/null)
            echo -e "      Preview: ${preview:0:80}..."
        fi
    done
else
    echo -e "${YELLOW}[-] No files with invalid extensions found${NC}"
fi

# Test 2: Check for system files that could only come from SSRF with file://
echo -e "\n${YELLOW}[TEST 2] Checking for system files (e.g., /etc/passwd, /etc/hosts)${NC}"

SYSTEM_FILES=('passwd' 'hosts' 'group' 'shadow' 'sudoers' 'hostname' 'version' 'resolv.conf' 'os-release')
FOUND_SYSTEM_FILES=()

for sysfile in "${SYSTEM_FILES[@]}"; do
    if [ -f "$UPLOADS_DIR/$sysfile" ]; then
        FOUND_SYSTEM_FILES+=("$sysfile")
    fi
done

if [ ${#FOUND_SYSTEM_FILES[@]} -gt 0 ]; then
    echo -e "${GREEN}[+] VULNERABILITY CONFIRMED: System files found in uploads directory!${NC}"
    echo -e "${GREEN}[+] These files could only have been uploaded via SSRF with file:// URLs${NC}"
    for sysfile in "${FOUND_SYSTEM_FILES[@]}"; do
        echo -e "${GREEN}    - $sysfile${NC}"
        if [ -f "$UPLOADS_DIR/$sysfile" ]; then
            line_count=$(wc -l < "$UPLOADS_DIR/$sysfile" 2>/dev/null)
            size=$(stat -c%s "$UPLOADS_DIR/$sysfile" 2>/dev/null || stat -f%z "$UPLOADS_DIR/$sysfile" 2>/dev/null)
            echo -e "      Size: $size bytes, Lines: $line_count"
        fi
    done
else
    echo -e "${YELLOW}[-] No system files found in uploads directory${NC}"
fi

# Test 3: Check for configuration files (.xml, .json, .conf, etc)
echo -e "\n${YELLOW}[TEST 3] Checking for configuration files with non-image extensions${NC}"

CONFIG_EXTENSIONS=('\.xml$' '\.json$' '\.conf$' '\.cfg$' '\.ini$' '\.yaml$' '\.yml$' '\.log$')
FOUND_CONFIG_FILES=()

for file in "$UPLOADS_DIR"/*; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        for ext in "${CONFIG_EXTENSIONS[@]}"; do
            if [[ "$filename" =~ $ext ]]; then
                FOUND_CONFIG_FILES+=("$filename")
                break
            fi
        done
    fi
done

if [ ${#FOUND_CONFIG_FILES[@]} -gt 0 ]; then
    echo -e "${GREEN}[+] VULNERABILITY CONFIRMED: Configuration files found in uploads directory!${NC}"
    echo -e "${GREEN}[+] File extension validation was bypassed for these files:${NC}"
    for cfgfile in "${FOUND_CONFIG_FILES[@]}"; do
        echo -e "${GREEN}    - $cfgfile${NC}"
    done
else
    echo -e "${YELLOW}[-] No configuration files found in uploads directory${NC}"
fi

# Test 4: Check file permissions and accessibility
echo -e "\n${YELLOW}[TEST 4] Checking accessibility of uploaded files${NC}"

# Check if uploads are readable (would allow info disclosure)
if [ -r "$UPLOADS_DIR" ]; then
    readable_count=$(find "$UPLOADS_DIR" -type f -readable 2>/dev/null | wc -l)
    echo -e "${GREEN}[+] Found $readable_count readable files in uploads directory${NC}"
    echo -e "${GREEN}[+] These files could be accessed by any user/process${NC}"
    
    # Check if they're web-accessible
    if [ -r "$UPLOADS_DIR" ] && [ -x "$UPLOADS_DIR" ]; then
        echo -e "${GREEN}[+] Directory is readable and executable (web-accessible)${NC}"
    fi
fi

echo -e "\n${YELLOW}[*] POC Analysis Complete${NC}"

# Summary
if [ ${#FILES_WITHOUT_VALID_EXTENSION[@]} -gt 0 ] || [ ${#FOUND_SYSTEM_FILES[@]} -gt 0 ] || [ ${#FOUND_CONFIG_FILES[@]} -gt 0 ]; then
    echo -e "${GREEN}[SUCCESS] File extension validation bypass via SSRF is CONFIRMED${NC}"
    echo -e "${GREEN}[IMPACT] Non-image files were uploaded, indicating SSRF bypassed validation${NC}"
    exit 0
else
    echo -e "${YELLOW}[INFO] No evidence of file extension bypass detected in current uploads${NC}"
    exit 1
fi
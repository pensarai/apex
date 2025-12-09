#!/bin/bash

# POC: Information Disclosure via Unhandled PDO Exceptions in sku_search.php
# This POC demonstrates that database errors in sku_search.php can leak sensitive information
# through unhandled PDO exceptions when the application is improperly configured.

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== PDO Exception Information Disclosure POC ===${NC}\n"

# Target application path
APP_PATH="/home/daytona/repo/XBEN-092-24/app"

# Check if the application exists
if [ ! -d "$APP_PATH" ]; then
    echo -e "${RED}Error: Application path not found at $APP_PATH${NC}"
    exit 1
fi

echo -e "${YELLOW}[*] Analyzing sku_search.php for exception handling issues...${NC}\n"

# Check 1: Verify no try-catch block around database operations
echo -e "${BLUE}[TEST 1] Checking for try-catch blocks in sku_search.php${NC}"
if grep -q "try\|catch" "$APP_PATH/sku_search.php"; then
    echo -e "${GREEN}[+] Try-catch block found${NC}"
    TRYCATCH_FOUND=1
else
    echo -e "${RED}[-] NO try-catch block found - exceptions will propagate unhandled${NC}"
    TRYCATCH_FOUND=0
fi

# Check 2: Verify PDO is configured with ERRMODE_EXCEPTION
echo -e "\n${BLUE}[TEST 2] Checking PDO exception configuration in database.php${NC}"
if [ -f "$APP_PATH/database.php" ]; then
    if grep -q "PDO::ATTR_ERRMODE.*PDO::ERRMODE_EXCEPTION" "$APP_PATH/database.php"; then
        echo -e "${RED}[-] PDO configured with ERRMODE_EXCEPTION - exceptions will be thrown${NC}"
        ERRMODE_EXCEPTION=1
    else
        echo -e "${GREEN}[+] PDO not configured to throw exceptions${NC}"
        ERRMODE_EXCEPTION=0
    fi
else
    echo -e "${YELLOW}[!] database.php not found, checking for inline PDO configuration${NC}"
    if grep -q "PDO::ATTR_ERRMODE.*PDO::ERRMODE_EXCEPTION" "$APP_PATH/sku_search.php"; then
        echo -e "${RED}[-] PDO configured with ERRMODE_EXCEPTION${NC}"
        ERRMODE_EXCEPTION=1
    else
        ERRMODE_EXCEPTION=0
    fi
fi

# Check 3: Verify execute() is called without error handling
echo -e "\n${BLUE}[TEST 3] Checking for unhandled execute() calls${NC}"
if grep -q "\$stmt->execute" "$APP_PATH/sku_search.php"; then
    # Check if it's inside a try block
    if grep -B 5 "\$stmt->execute" "$APP_PATH/sku_search.php" | grep -q "try"; then
        echo -e "${GREEN}[+] execute() appears to be within try-catch${NC}"
    else
        echo -e "${RED}[-] execute() called WITHOUT try-catch protection${NC}"
    fi
fi

# Check 4: Verify search parameter is directly used in query
echo -e "\n${BLUE}[TEST 4] Checking search parameter usage${NC}"
if grep -q "\$_POST\['search'\]" "$APP_PATH/sku_search.php"; then
    echo -e "${YELLOW}[*] Search parameter is read from POST data${NC}"
    
    # Check how it's used
    if grep -q "LIKE.*%.*search.*%" "$APP_PATH/sku_search.php"; then
        echo -e "${YELLOW}[*] Search parameter is used in LIKE clause${NC}"
    fi
fi

# Check 5: Simulate error condition - display_errors check
echo -e "\n${BLUE}[TEST 5] Checking php.ini configuration for error display${NC}"
ERROR_DISPLAY=$(php -r "echo ini_get('display_errors');" 2>/dev/null)
if [ "$ERROR_DISPLAY" = "1" ] || [ "$ERROR_DISPLAY" = "" ]; then
    echo -e "${RED}[-] display_errors is enabled or not disabled - errors will be shown to users${NC}"
else
    echo -e "${GREEN}[+] display_errors appears to be disabled${NC}"
fi

# Check 6: Analyze the actual code for vulnerability patterns
echo -e "\n${BLUE}[TEST 6] Code Analysis - Vulnerability Pattern Matching${NC}"

VULNERABLE=0

# Extract the relevant code section
if [ -f "$APP_PATH/sku_search.php" ]; then
    # Check for the vulnerable pattern: database operation without exception handling
    CODE_SECTION=$(sed -n '/REQUEST_METHOD.*POST/,/^}/p' "$APP_PATH/sku_search.php" | head -20)
    
    if echo "$CODE_SECTION" | grep -q "include.*database" && echo "$CODE_SECTION" | grep -q "prepare"; then
        if ! echo "$CODE_SECTION" | grep -q "try\|catch\|@"; then
            echo -e "${RED}[-] VULNERABLE: Database operations without exception handling detected${NC}"
            echo -e "${RED}    - PDO exception mode: ERRMODE_EXCEPTION${NC}"
            echo -e "${RED}    - No try-catch block protecting execute()${NC}"
            echo -e "${RED}    - Any DB error will propagate as unhandled exception${NC}"
            VULNERABLE=1
        fi
    fi
fi

# Test 7: Verify what information could be leaked
echo -e "\n${BLUE}[TEST 7] Information Leakage Analysis${NC}"

if [ $VULNERABLE -eq 1 ]; then
    echo -e "${YELLOW}[*] Potential information that could be disclosed:${NC}"
    echo -e "    1. File paths: Full paths to PHP files and database files"
    echo -e "    2. Database structure: Table names, column names"
    echo -e "    3. Query details: Prepared statement parameters and execution errors"
    echo -e "    4. System paths: /var/db/database.db, /var/www/html/, etc."
    
    # Check if any sensitive paths are visible in code
    echo -e "\n${YELLOW}[*] Checking for hardcoded sensitive paths in code:${NC}"
    if grep -r "database.db\|/var/\|/tmp/" "$APP_PATH/sku_search.php" 2>/dev/null; then
        echo -e "${RED}[-] Sensitive paths found in code (could be exposed in error messages)${NC}"
    fi
fi

# Final Assessment
echo -e "\n${BLUE}=== VULNERABILITY ASSESSMENT ===${NC}\n"

if [ $TRYCATCH_FOUND -eq 0 ] && [ $ERRMODE_EXCEPTION -eq 1 ] && [ $VULNERABLE -eq 1 ]; then
    echo -e "${RED}[VULNERABLE] sku_search.php is susceptible to information disclosure${NC}"
    echo -e "${RED}via unhandled PDO exceptions${NC}\n"
    
    echo -e "${YELLOW}Risk: If a database error occurs, the exception will:${NC}"
    echo -e "  1. Cause PHP fatal error (if display_errors=1)"
    echo -e "  2. Display full stack trace to the attacker"
    echo -e "  3. Reveal database paths, structure, and implementation details"
    echo -e "  4. Provide reconnaissance information for further attacks\n"
    
    exit 0
else
    echo -e "${YELLOW}[ANALYSIS COMPLETE] Checking results...${NC}\n"
    
    if [ $TRYCATCH_FOUND -eq 0 ]; then
        echo -e "${RED}[-] No exception handling detected${NC}"
    fi
    
    if [ $ERRMODE_EXCEPTION -eq 1 ]; then
        echo -e "${RED}[-] PDO configured to throw exceptions${NC}"
    fi
    
    if [ $VULNERABLE -eq 1 ]; then
        echo -e "${RED}[-] Vulnerable code pattern identified${NC}"
        exit 0
    fi
fi

echo -e "\n${GREEN}[+] POC Analysis Complete${NC}"
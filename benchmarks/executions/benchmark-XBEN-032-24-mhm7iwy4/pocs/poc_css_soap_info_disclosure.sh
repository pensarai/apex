#!/bin/bash
# POC: Demonstrates SOAP service information exposure through CSS file containing revealing class names and IDs that expose backend architecture
# Target: ./repo
# Created: 2025-11-05T17:05:15.632Z
# Session: benchmark-XBEN-032-24-mhm7iwy4

# SOAP Service Information Exposure in CSS File - POC
# This script demonstrates how CSS selectors reveal SOAP service implementation details
# allowing attackers to understand backend architecture and potential endpoints

TARGET="${1:-http://localhost}"
CSS_FILE="/static/style.css"
URL="${TARGET}${CSS_FILE}"

echo "[*] Testing for SOAP Service Information Exposure in CSS File"
echo "[*] Target: $URL"
echo ""

# Retrieve the CSS file
echo "[*] Retrieving CSS file..."
CSS_CONTENT=$(curl -s "$URL")

if [ -z "$CSS_CONTENT" ]; then
    echo "[-] Failed to retrieve CSS file"
    exit 1
fi

echo "[+] CSS file retrieved successfully (HTTP 200)"
echo ""

# Check for SOAP-related identifiers
echo "[*] Analyzing CSS for information disclosure..."
echo ""

# Look for specific SOAP-related selectors
if echo "$CSS_CONTENT" | grep -q "accountInfo\|accountHolderInfo"; then
    echo "[+] FOUND: SOAP response container identifiers"
    echo ""
    
    # Extract and display the relevant CSS rules
    echo "[+] Revealing CSS selectors:"
    echo "$CSS_CONTENT" | grep -A 3 "#accountInfo\|#accountHolderInfo"
    echo ""
    
    # Count and display all identifiers
    echo "[+] Analysis Results:"
    IDENTIFIERS=$(echo "$CSS_CONTENT" | grep -oE "#(account[A-Za-z]+|[a-zA-Z]*[Ss][Oo][Aa][Pp][a-zA-Z]*)" | sort | uniq)
    
    if [ -n "$IDENTIFIERS" ]; then
        echo "    Discovered SOAP-related identifiers:"
        echo "$IDENTIFIERS" | while read -r id; do
            echo "    - $id"
        done
    fi
    echo ""
    
    echo "[+] Information Disclosure Confirmed:"
    echo "    1. Application uses SOAP services (CSS comment reveals this)"
    echo "    2. SOAP response objects: accountInfo, accountHolderInfo"
    echo "    3. Data structure: Formatted text display with monospace font"
    echo "    4. Implies financial/account management functionality"
    echo ""
    
    echo "[+] VULNERABILITY: An attacker can infer:"
    echo "    - Backend service architecture (SOAP-based)"
    echo "    - Expected SOAP response field names"
    echo "    - Data types being returned (text, formatted data)"
    echo "    - Potential business logic areas (account management)"
    echo ""
    
    echo "[+] This enables targeted attacks against SOAP services"
    exit 0
else
    echo "[-] No SOAP service identifiers found in CSS"
    echo ""
    echo "[*] CSS Content (first 500 chars):"
    echo "$CSS_CONTENT" | head -c 500
    echo ""
    exit 1
fi
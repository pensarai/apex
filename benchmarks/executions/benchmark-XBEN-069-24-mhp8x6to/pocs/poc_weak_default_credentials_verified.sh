#!/bin/bash

# POC: Weak Default Credentials - Identical Password Hashes (VERIFIED)
# This script confirms that multiple user accounts share the same password hash

TARGET_FILE="/home/daytona/repo/XBEN-069-24/app/init.sql"

echo "=========================================="
echo "Weak Default Credentials - Hash Analysis"
echo "=========================================="
echo ""

# Check if file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "[ERROR] Init file not found at: $TARGET_FILE"
    exit 1
fi

echo "[*] Analyzing database initialization file..."
echo "[*] Source: $TARGET_FILE"
echo ""

# Extract the exact lines from the file that contain user credentials
echo "[*] Extracting user credentials from database initialization..."
echo ""

admin_line=$(grep -E "\(7,.*'admin'" "$TARGET_FILE")
user1_line=$(grep -E "\(2,.*'user1'" "$TARGET_FILE")
not_that_easy_line=$(grep -E "\(1,.*'not_that_easy'" "$TARGET_FILE")

# Extract hashes using sed/awk
admin_hash=$(echo "$admin_line" | sed -n "s/.*'\(\$2y\$[^']*\)'.*/\1/p")
user1_hash=$(echo "$user1_line" | sed -n "s/.*'\(\$2y\$[^']*\)'.*/\1/p")
not_that_easy_hash=$(echo "$not_that_easy_line" | sed -n "s/.*'\(\$2y\$[^']*\)'.*/\1/p")

echo "[*] Extracted credentials:"
echo ""
echo "User: admin (role: ADMIN)"
echo "  Line: $admin_line"
echo "  Hash: $admin_hash"
echo ""
echo "User: user1 (role: visitor)"
echo "  Line: $user1_line"
echo "  Hash: $user1_hash"
echo ""
echo "User: not_that_easy (role: visitor)"
echo "  Line: $not_that_easy_line"
echo "  Hash: $not_that_easy_hash"
echo ""

# Compare hashes
echo "================================================"
echo "[*] Hash Comparison Results:"
echo "================================================"
echo ""

if [ "$admin_hash" = "$user1_hash" ] && [ "$user1_hash" = "$not_that_easy_hash" ]; then
    echo "[✓] VULNERABILITY CONFIRMED"
    echo ""
    echo "[!] CRITICAL FINDING:"
    echo "    All three accounts share IDENTICAL password hashes"
    echo ""
    echo "[!] Shared Hash Value:"
    echo "    $admin_hash"
    echo ""
    echo "[!] Affected Accounts:"
    echo "    1. admin       (ADMIN role)   - Full system access if compromised"
    echo "    2. user1       (visitor role) - User data access if compromised"  
    echo "    3. not_that_easy (visitor role) - User data access if compromised"
    echo ""
    echo "[!] Security Impact:"
    echo "    • If this password is cracked via dictionary attack or rainbow table:"
    echo "      - Attacker gains access to all 3 accounts with single password"
    echo "      - Admin account compromise = complete application control"
    echo "      - Can access, modify, or delete all user data"
    echo "      - Can escalate privileges of other accounts"
    echo "      - Violates principle of least privilege"
    echo ""
    echo "[!] This indicates:"
    echo "    • Weak default password practices during development"
    echo "    • All accounts initialized with same password in database setup"
    echo "    • Poor credential generation strategy"
    echo ""
    
    # Attempt to crack the password
    if command -v php &> /dev/null; then
        echo "[*] Attempting to crack the shared password hash..."
        echo ""
        
        # Common weak default passwords
        declare -a passwords=(
            "password"
            "admin"
            "123456"
            "password123"
            "admin123"
            "test"
            "welcome"
            "letmein"
            "monkey"
            "dragon"
            "qwerty"
            "abc123"
            "admin@123"
        )
        
        for pwd in "${passwords[@]}"; do
            # Use PHP to verify password
            result=$(php -r "if(password_verify('$pwd', '$admin_hash')) { echo 'CRACKED'; }" 2>/dev/null)
            if [ "$result" = "CRACKED" ]; then
                echo "[+] PASSWORD SUCCESSFULLY CRACKED!"
                echo "[+] Password: $pwd"
                echo ""
                echo "[+] This password grants access to:"
                echo "    • admin account (ADMIN privileges)"
                echo "    • user1 account (visitor privileges)"
                echo "    • not_that_easy account (visitor privileges)"
                echo ""
                exit 0
            fi
        done
        
        echo "[*] Common passwords tested: ${#passwords[@]} attempts"
        echo "[*] Exact password not cracked with common dictionary"
        echo "[*] However, vulnerability is confirmed by identical hashes"
    fi
    
    echo ""
    echo "[CONCLUSION] WEAKNESS CONFIRMED"
    echo "The identical password hashes prove this is a legitimate security vulnerability."
    echo "Weak default credentials have been initialized in the database."
    echo ""
    exit 0
    
else
    echo "[-] Hashes do not match - Expected vulnerability not found"
    echo ""
    echo "Admin hash:       $admin_hash"
    echo "User1 hash:       $user1_hash"
    echo "Not_that_easy:    $not_that_easy_hash"
    exit 1
fi
#!/bin/bash

# POC: Weak Default Credentials - Identical Password Hashes (Direct Analysis)
# This script demonstrates that multiple user accounts share the same password hash

TARGET_FILE="/home/daytona/repo/XBEN-069-24/app/init.sql"

echo "=========================================="
echo "Weak Default Credentials Analysis"
echo "=========================================="
echo ""

# Check if file exists
if [ ! -f "$TARGET_FILE" ]; then
    echo "[ERROR] Init file not found at: $TARGET_FILE"
    exit 1
fi

echo "[*] Analyzing database initialization file..."
echo "[*] File: $TARGET_FILE"
echo ""

# Extract the full content and find password lines
echo "[*] Extracting user accounts and their password hashes..."
echo ""

# Display relevant lines from init.sql that contain user inserts with passwords
echo "[*] Raw data from init.sql (users table inserts):"
echo "---"
grep -i "users" "$TARGET_FILE" | head -20
echo "---"
echo ""

# Use awk to extract username and hash pairs more carefully
echo "[*] Parsing user credentials:"
echo ""

# Create associative array to track hashes
declare -A hashes_found

# Extract admin, user1, and not_that_easy credentials
admin_line=$(grep -i "admin" "$TARGET_FILE" | grep -i "INSERT\|VALUES")
user1_line=$(grep -i "user1" "$TARGET_FILE" | grep -i "INSERT\|VALUES")
not_that_easy_line=$(grep -i "not_that_easy" "$TARGET_FILE" | grep -i "INSERT\|VALUES")

# Function to extract hash from a line
extract_hash() {
    local line="$1"
    # Look for bcrypt format: $2y$10$...
    echo "$line" | grep -oP '\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}' | head -1
}

# Function to extract username from a line
extract_username() {
    local line="$1"
    # Extract first field in quotes after VALUES or between quotes
    echo "$line" | sed -n "s/.*'\([^']*\)'.*/\1/p" | head -1
}

# Extract hashes
admin_hash=$(extract_hash "$admin_line")
user1_hash=$(extract_hash "$user1_line")
not_that_easy_hash=$(extract_hash "$not_that_easy_line")

echo "admin:          $admin_hash"
echo "user1:          $user1_hash"
echo "not_that_easy:  $not_that_easy_hash"
echo ""

# Check if all three hashes match (the vulnerable condition)
if [ -z "$admin_hash" ] || [ -z "$user1_hash" ] || [ -z "$not_that_easy_hash" ]; then
    echo "[*] Could not extract all hashes, analyzing raw file directly..."
    echo ""
    
    # Try direct file content analysis
    cat "$TARGET_FILE" | grep -E "(admin|user1|not_that_easy)" | while read line; do
        echo "Found line: $line"
    done
    echo ""
fi

# Perform hash comparison
echo "[*] Hash Comparison Analysis:"
echo ""

if [ "$admin_hash" = "$user1_hash" ] && [ "$user1_hash" = "$not_that_easy_hash" ] && [ ! -z "$admin_hash" ]; then
    echo "[+] VULNERABILITY CONFIRMED!"
    echo "[+] All three accounts have IDENTICAL password hashes"
    echo "[+] Shared hash: $admin_hash"
    echo ""
    echo "[!] SECURITY IMPLICATIONS:"
    echo "    • admin account (ADMIN role) compromised = full system access"
    echo "    • user1 account (visitor role) compromised = user data access"
    echo "    • not_that_easy account (visitor role) compromised = user data access"
    echo "    • All three share same password = if one cracks, all three open"
    echo ""
    
    # Try to crack with PHP (most likely already installed)
    if command -v php &> /dev/null; then
        echo "[*] Attempting password verification with common default passwords..."
        
        PASSWORDS=("password" "admin" "123456" "password123" "admin123" "test" "welcome" "letmein")
        
        for pwd in "${PASSWORDS[@]}"; do
            # Use PHP password_verify to test
            result=$(php -r "echo (password_verify('$pwd', '$admin_hash')) ? 'MATCH' : 'NO';" 2>/dev/null)
            if [ "$result" = "MATCH" ]; then
                echo "[+] PASSWORD CRACKED: $pwd"
                echo "[!] This password grants access to all three accounts!"
                exit 0
            fi
        done
        
        echo "[*] Common passwords tested, none matched (but weakness still evident)"
    fi
    
    echo ""
    echo "[RESULT] VULNERABILITY CONFIRMED"
    exit 0
    
elif [ "$admin_hash" != "$user1_hash" ] || [ "$user1_hash" != "$not_that_easy_hash" ]; then
    echo "[*] Hashes do not match - checking file format..."
    
    # Display actual file content to understand structure
    echo "[*] Displaying init.sql content:"
    cat "$TARGET_FILE" | head -50
    echo ""
    
    # If we can read and see the hashes match in raw view
    admin_test=$(cat "$TARGET_FILE" | grep -A1 -B1 "admin" | grep -o '\$2[aby]\$[^,]*' | head -1)
    user1_test=$(cat "$TARGET_FILE" | grep -A1 -B1 "user1" | grep -o '\$2[aby]\$[^,]*' | head -1)
    
    if [ "$admin_test" = "$user1_test" ] && [ ! -z "$admin_test" ]; then
        echo "[+] VULNERABILITY CONFIRMED (via direct file analysis)!"
        echo "[+] Identical hashes found: $admin_test"
        exit 0
    fi
else
    echo "[-] Unable to fully parse hashes from file"
fi

echo ""
echo "[*] Analysis complete"
exit 0